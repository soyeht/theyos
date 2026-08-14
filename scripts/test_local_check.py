#!/usr/bin/env python3
"""Tests for scripts/local_check.py.

The tool's job is to be believed when it says the compile surface is green, so what is
tested here is the set of ways it could say "green" without having compiled anything.
Each negative test constructs that exact shape and asserts the tool refuses; where a
lookalike must stay green, it is pinned beside it, because a predicate is only stated
once both of its sides are held.

Nothing here invokes cargo. The matrix module is a stub, so these run in milliseconds
and stay honest on a machine with no Rust toolchain at all.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import types
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent / "local_check.py"

# The interpreter is the one executable guaranteed on every host this runs on.
# `/bin/true` exists on Linux and NOT on macOS, so hardcoding it would make
# these tests pass on the runner and fail on half the developer machines.
OK_CMD = [sys.executable, "-c", ""]
FAIL_CMD = [sys.executable, "-c", "raise SystemExit(1)"]


def load_module():
    spec = importlib.util.spec_from_file_location("local_check_under_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Row:
    """The only surface local_check uses from a matrix row."""

    def __init__(self, name: str) -> None:
        self.name = name


def stub_matrix(module, names, command=None, rust_dir=None):
    """A stand-in for `cargo_test_matrix` with no cargo behind it.

    `rust_dir` defaults to the temporary cache because it becomes the child's cwd: a path
    that does not exist makes every row fail with FileNotFoundError, which is a defect in
    the test rather than in the tool, and it looks exactly like a real red.
    """
    stub = types.SimpleNamespace()
    stub.matrix = lambda: [Row(n) for n in names]
    stub.command = command or (lambda row: OK_CMD)
    stub.RUST = rust_dir or str(module.CACHE)
    return stub


@contextlib.contextmanager
def temp_cache(module):
    with tempfile.TemporaryDirectory() as tmp:
        cache = Path(tmp) / "cache"
        cache.mkdir()
        old_cache, old_stamp = module.CACHE, module.WORKERS_STAMP
        module.CACHE = cache
        module.WORKERS_STAMP = cache / "workers"
        try:
            yield cache
        finally:
            module.CACHE, module.WORKERS_STAMP = old_cache, old_stamp


def run_tier2(module, stub, workers=2, jobs=1):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = module.tier2(stub, workers, jobs)
    return rc, buf.getvalue()


class EmptyMatrixIsNotAPass(unittest.TestCase):
    """Zero rows must not read as twenty-six rows that all passed instantly."""

    def test_zero_rows_is_refused(self):
        module = load_module()
        with temp_cache(module):
            rc, out = run_tier2(module, stub_matrix(module, []))
        self.assertEqual(rc, 2, "an empty matrix must not exit 0")
        self.assertIn("zero rows", out)

    def test_a_real_matrix_still_passes(self):
        # The lookalike. Without this, a tier2 that refused everything would satisfy the
        # test above and prove nothing about the guard.
        module = load_module()
        with temp_cache(module):
            rc, out = run_tier2(module, stub_matrix(module, ["a", "b", "c"]))
        self.assertEqual(rc, 0, out)
        self.assertIn("all 3 feature combinations compile", out)


class ARowThatCannotRunIsAFailure(unittest.TestCase):
    """One broken row must not discard the verdicts already paid for."""

    def test_exception_in_one_row_fails_that_row_and_keeps_the_rest(self):
        module = load_module()

        def command(row):
            if row.name == "boom":
                raise OSError("no such executable")
            return OK_CMD

        with temp_cache(module):
            rc, out = run_tier2(module, stub_matrix(module, ["a", "boom", "c"], command))
        self.assertEqual(rc, 1, out)
        self.assertIn("boom", out)
        # The whole pass still ran: the guard on reported-vs-derived must not fire.
        self.assertNotIn("not a pass", out)

    def test_a_nonzero_row_is_reported_red(self):
        module = load_module()
        with temp_cache(module):
            rc, out = run_tier2(
                module, stub_matrix(module, ["ok", "bad"],
                                    lambda row: FAIL_CMD if row.name == "bad"
                                    else OK_CMD))
        self.assertEqual(rc, 1, out)
        self.assertIn("bad", out)


class ChangingWorkersInvalidatesTheCacheOutLoud(unittest.TestCase):
    """Row i lives in dir i%workers, so a changed count silently throws the cache away."""

    def test_the_change_is_announced(self):
        module = load_module()
        with temp_cache(module):
            run_tier2(module, stub_matrix(module, ["a", "b", "c", "d"]), workers=2)
            rc, out = run_tier2(module, stub_matrix(module, ["a", "b", "c", "d"]), workers=4)
        self.assertEqual(rc, 0, out)
        self.assertIn("worker count changed 2 -> 4", out)

    def test_an_unchanged_count_reports_warm(self):
        module = load_module()
        with temp_cache(module):
            run_tier2(module, stub_matrix(module, ["a", "b"]), workers=2)
            rc, out = run_tier2(module, stub_matrix(module, ["a", "b"]), workers=2)
        self.assertEqual(rc, 0, out)
        self.assertIn("warm", out)
        self.assertNotIn("worker count changed", out)


class DerivationFailureIsNotAPass(unittest.TestCase):
    def test_matrix_raising_is_refused(self):
        module = load_module()
        stub = types.SimpleNamespace()

        def boom():
            raise RuntimeError("cargo metadata exploded")

        stub.matrix = boom
        with temp_cache(module):
            rc, out = run_tier2(module, stub)
        self.assertEqual(rc, 2, "a matrix that could not be derived must not exit 0")
        self.assertIn("could not derive", out)


class OldPythonSaysSoInsteadOfCrashing(unittest.TestCase):
    """tomllib is 3.11+; the message must name the cause and point at tier 1."""

    def test_missing_tomllib_is_explained(self):
        module = load_module()
        real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) \
            else __builtins__.__import__

        def fake_import(name, *a, **kw):
            if name == "cargo_test_matrix":
                raise ModuleNotFoundError("No module named 'tomllib'", name="tomllib")
            return real_import(name, *a, **kw)

        buf = io.StringIO()
        builtins_mod = sys.modules["builtins"]
        builtins_mod.__import__ = fake_import
        try:
            with contextlib.redirect_stdout(buf):
                result = module.load_matrix_module()
        finally:
            builtins_mod.__import__ = real_import
        self.assertIsNone(result)
        self.assertIn("Python 3.11", buf.getvalue())
        self.assertIn("--tier1", buf.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
