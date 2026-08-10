#!/usr/bin/env python3
"""Tests for scripts/check_consumption_coverage.py.

The negative tests are the point.  A positive test cannot catch a gate that
stopped gating, so every consumption class the gate claims to handle is
constructed here in a throwaway fake repo and asserted to go red when it ought
to and green when restored:

  * include_str! / include_bytes! of a file the backend paths do not cover -> RED
  * a build.rs literal read of an uncovered file -> RED
  * concat!(env!("CARGO_MANIFEST_DIR"), ...) of an uncovered file -> RED
  * the same, with the file under a covered glob -> covered (OK), still green
  * read_dir(...) -> DECLARED (listed, never silent) but not a failure by itself
  * completeness: a PROVE-class the parser went blind to (a planted probe that
    the regex no longer sees) -> RED even with nothing else wrong
  * coverage-glob drift: a backend-ci.yml this parser cannot read -> exit 2
    (fail closed), never a silent empty covered set
  * partition drift or missing self-certification in either real/shim pair -> exit 2
"""

from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("check_consumption_coverage.py")
SPEC = importlib.util.spec_from_file_location("check_consumption_coverage", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)

MATRIX_SCRIPT = Path(__file__).with_name("cargo_test_matrix.py")
MATRIX_SPEC = importlib.util.spec_from_file_location("cargo_test_matrix", MATRIX_SCRIPT)
assert MATRIX_SPEC is not None and MATRIX_SPEC.loader is not None
matrix = importlib.util.module_from_spec(MATRIX_SPEC)
sys.modules[MATRIX_SPEC.name] = matrix
MATRIX_SPEC.loader.exec_module(matrix)


BACKEND_CI = """\
name: Backend CI
on:
  push:
    paths:
      - "admin/rust/**"
      - "scripts/**"
      - ".github/workflows/backend-ci.yml"
      - ".github/workflows/backend-ci-docs-shim.yml"
  pull_request:
    paths:
      - "admin/rust/**"
      - "scripts/**"
      - ".github/workflows/backend-ci.yml"
      - ".github/workflows/backend-ci-docs-shim.yml"
"""

BACKEND_SHIM = """\
name: Backend CI (docs-only shim)
on:
  pull_request:
    paths-ignore:
      - "admin/rust/**"
      - "scripts/**"
      - ".github/workflows/backend-ci.yml"
      - ".github/workflows/backend-ci-docs-shim.yml"
"""

HOMEBREW_CI = """\
name: Homebrew Smoke (macOS)
on:
  push:
    branches:
      - main
    paths:
      - "homebrew/**"
      - ".github/workflows/homebrew-smoke-macos.yml"
      - ".github/workflows/homebrew-smoke-docs-shim.yml"
  pull_request:
    paths:
      - "homebrew/**"
      - ".github/workflows/homebrew-smoke-macos.yml"
      - ".github/workflows/homebrew-smoke-docs-shim.yml"
"""

HOMEBREW_SHIM = """\
name: Homebrew Smoke (docs-only shim)
on:
  pull_request:
    paths-ignore:
      - "homebrew/**"
      - ".github/workflows/homebrew-smoke-macos.yml"
      - ".github/workflows/homebrew-smoke-docs-shim.yml"
"""


def _build_repo(tmp: Path, lib_rs: str, build_rs: str | None = None) -> Path:
    """Lay out a minimal fake repo with one crate under admin/rust."""
    (tmp / ".github" / "workflows").mkdir(parents=True)
    (tmp / ".github" / "workflows" / "backend-ci.yml").write_text(BACKEND_CI, encoding="utf-8")
    (tmp / ".github" / "workflows" / "backend-ci-docs-shim.yml").write_text(BACKEND_SHIM, encoding="utf-8")
    (tmp / ".github" / "workflows" / "homebrew-smoke-macos.yml").write_text(
        HOMEBREW_CI, encoding="utf-8"
    )
    (tmp / ".github" / "workflows" / "homebrew-smoke-docs-shim.yml").write_text(
        HOMEBREW_SHIM, encoding="utf-8"
    )

    crate = tmp / "admin" / "rust" / "cratea"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text("[package]\nname = \"cratea\"\nversion = \"0.1.0\"\n", encoding="utf-8")
    (crate / "src" / "lib.rs").write_text(lib_rs, encoding="utf-8")
    # A sibling under admin/rust -> always covered.
    (crate / "src" / "sibling.txt").write_text("covered\n", encoding="utf-8")
    if build_rs is not None:
        (crate / "build.rs").write_text(build_rs, encoding="utf-8")
    return tmp


def _run(repo: Path, *probe_kinds: str) -> tuple[int, str]:
    buf = io.StringIO()
    try:
        rc = gate.run(repo, repo / ".github" / "workflows" / "backend-ci.yml", set(probe_kinds), out=buf)
    except gate.GateCannotRun:
        rc = 2
    return rc, buf.getvalue()


class ConsumptionCoverageTests(unittest.TestCase):
    def test_covered_include_is_green(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(Path(d), 'const S: &str = include_str!("sibling.txt");\n')
            rc, out = _run(repo)
            self.assertEqual(rc, 0, out)
            self.assertIn("OK   admin/rust/cratea/src/sibling.txt", out)

    def test_include_str_uncovered_is_red_and_restores(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(Path(d), "")
            # plant
            (repo / "admin" / "rust" / "cratea" / "src" / "lib.rs").write_text(
                'const U: &str = include_str!("../../../../uncovered_at_root.md");\n', encoding="utf-8"
            )
            rc, out = _run(repo)
            self.assertEqual(rc, 1, out)
            self.assertIn("RED  uncovered_at_root.md", out)
            # restore
            (repo / "admin" / "rust" / "cratea" / "src" / "lib.rs").write_text(
                'const S: &str = include_str!("sibling.txt");\n', encoding="utf-8"
            )
            rc, out = _run(repo)
            self.assertEqual(rc, 0, out)

    def test_include_bytes_uncovered_is_red(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(
                Path(d),
                'const B: &[u8] = include_bytes!("../../../../uncovered_bytes.bin");\n',
            )
            rc, out = _run(repo, "include_bytes!")
            self.assertEqual(rc, 1, out)
            self.assertIn("RED  uncovered_bytes.bin", out)
            self.assertIn("include_bytes!", out)

    def test_uncovered_golden_is_counted_by_path_not_use(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(
                Path(d),
                'const A: &str = include_str!("../../../../one.md");\n'
                'const B: &str = include_str!("../../../../one.md");\n',
            )
            rc, out = _run(repo)
            self.assertEqual(rc, 1, out)
            self.assertIn("UNCOVERED consumed paths (1)", out)
            self.assertIn("result: FAIL (1 uncovered paths", out)

    def test_buildrs_read_uncovered_is_red(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(
                Path(d),
                "// nothing in lib.rs\n",
                build_rs=(
                    "fn main() {\n"
                    '    let _ = std::fs::read_to_string("../../../uncovered_build.md").unwrap();\n'
                    "}\n"
                ),
            )
            rc, out = _run(repo, "build.rs-read")
            self.assertEqual(rc, 1, out)
            self.assertIn("RED  uncovered_build.md", out)
            self.assertIn("build.rs-read", out)

    def test_concat_cmdir_uncovered_is_red(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(
                Path(d),
                'const C: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../uncovered_cmdir.md");\n',
            )
            rc, out = _run(repo, "concat-cmdir")
            self.assertEqual(rc, 1, out)
            self.assertIn("RED  uncovered_cmdir.md", out)
            self.assertIn("concat-cmdir", out)

    def test_read_dir_is_declared_not_red(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(
                Path(d),
                'const S: &str = include_str!("sibling.txt");\n'
                "fn _x() { let _ = std::fs::read_dir(\".\"); }\n",
            )
            rc, out = _run(repo)
            # read_dir is detected and declared, but alone is not a failure.
            self.assertEqual(rc, 0, out)
            self.assertIn("DEC  admin/rust/cratea/src/lib.rs", out)
            self.assertIn("read_dir", out)

    def test_completeness_blind_class_is_red(self):
        """If a PROBE-class is declared but the parser finds none, the gate is
        blind to that class and must go red even with nothing else wrong."""
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(Path(d), 'const S: &str = include_str!("sibling.txt");\n')
            rc, out = _run(repo, "include_bytes!")  # claimed, but none present
            self.assertEqual(rc, 1, out)
            self.assertIn("GATE COMPLETENESS FAILURE", out)
            self.assertIn("blind to PROVE-class 'include_bytes!'", out)

    def test_completeness_satisfied_when_present(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(
                Path(d),
                'const B: &[u8] = include_bytes!("../../../../u.bin");\n',
            )
            rc, out = _run(repo, "include_bytes!")  # present -> no blind error, just the RED
            self.assertEqual(rc, 1, out)
            self.assertNotIn("GATE COMPLETENESS FAILURE", out)
            self.assertIn("RED  u.bin", out)

    def test_paths_parser_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(Path(d), 'const S: &str = include_str!("sibling.txt");\n')
            # rewrite backend-ci.yml into a shape the parser cannot read.
            (repo / ".github" / "workflows" / "backend-ci.yml").write_text(
                "name: Backend CI\non: [workflow_dispatch]\n", encoding="utf-8"
            )
            rc, out = _run(repo)
            self.assertEqual(rc, 2, out)  # fail closed, never an empty covered set

    def test_shim_partition_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(Path(d), 'const S: &str = include_str!("sibling.txt");\n')
            shim = repo / ".github" / "workflows" / "backend-ci-docs-shim.yml"
            shim.write_text(BACKEND_SHIM.replace('      - "admin/rust/**"\n', ""), encoding="utf-8")
            with self.assertRaisesRegex(
                gate.GateCannotRun,
                "backend-ci.yml pull_request paths and backend-ci-docs-shim.yml paths-ignore differ",
            ):
                gate.run(
                    repo,
                    repo / ".github" / "workflows" / "backend-ci.yml",
                    set(),
                    out=io.StringIO(),
                )

    def test_push_partition_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(Path(d), 'const S: &str = include_str!("sibling.txt");\n')
            backend = repo / ".github" / "workflows" / "backend-ci.yml"
            text = backend.read_text(encoding="utf-8")
            push, pull_request = text.split("  pull_request:\n", 1)
            push = push.replace('      - "admin/rust/**"\n', "")
            backend.write_text(push + "  pull_request:\n" + pull_request, encoding="utf-8")
            with self.assertRaisesRegex(
                gate.GateCannotRun, "backend-ci.yml push paths and pull_request paths differ"
            ):
                gate.run(repo, backend, set(), out=io.StringIO())

    def test_homebrew_push_partition_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(Path(d), 'const S: &str = include_str!("sibling.txt");\n')
            real = repo / ".github" / "workflows" / "homebrew-smoke-macos.yml"
            text = real.read_text(encoding="utf-8")
            push, pull_request = text.split("  pull_request:\n", 1)
            push = push.replace('      - "homebrew/**"\n', "")
            real.write_text(push + "  pull_request:\n" + pull_request, encoding="utf-8")
            with self.assertRaisesRegex(
                gate.GateCannotRun,
                "homebrew-smoke-macos.yml push paths and pull_request paths differ",
            ):
                gate.run(
                    repo,
                    repo / ".github" / "workflows" / "backend-ci.yml",
                    set(),
                    out=io.StringIO(),
                )

    def test_homebrew_shim_partition_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(Path(d), 'const S: &str = include_str!("sibling.txt");\n')
            shim = repo / ".github" / "workflows" / "homebrew-smoke-docs-shim.yml"
            shim.write_text(
                HOMEBREW_SHIM.replace('      - "homebrew/**"\n', ""), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                gate.GateCannotRun,
                "homebrew-smoke-macos.yml pull_request paths and "
                "homebrew-smoke-docs-shim.yml paths-ignore differ",
            ):
                gate.run(
                    repo,
                    repo / ".github" / "workflows" / "backend-ci.yml",
                    set(),
                    out=io.StringIO(),
                )

    def test_homebrew_shim_self_certification_missing_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(Path(d), 'const S: &str = include_str!("sibling.txt");\n')
            real = repo / ".github" / "workflows" / "homebrew-smoke-macos.yml"
            shim = repo / ".github" / "workflows" / "homebrew-smoke-docs-shim.yml"
            missing = '      - ".github/workflows/homebrew-smoke-docs-shim.yml"\n'
            real.write_text(HOMEBREW_CI.replace(missing, ""), encoding="utf-8")
            shim.write_text(HOMEBREW_SHIM.replace(missing, ""), encoding="utf-8")
            with self.assertRaisesRegex(
                gate.GateCannotRun,
                "homebrew-smoke-macos.yml/homebrew-smoke-docs-shim.yml "
                "self-certification missing .github/workflows/homebrew-smoke-docs-shim.yml",
            ):
                gate.run(
                    repo,
                    repo / ".github" / "workflows" / "backend-ci.yml",
                    set(),
                    out=io.StringIO(),
                )

    def test_runtime_literal_is_covered(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(Path(d), 'const _: &[u8] = repo_test_file!("scripts/peer.py");\n')
            (repo / "scripts").mkdir()
            (repo / "scripts" / "peer.py").write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            rc, out = _run(repo, "repo_test_file!")
            self.assertEqual(rc, 0, out)
            self.assertIn("repo_test_file!", out)

    def test_runtime_path_bypass_is_red(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(Path(d), 'const S: &str = include_str!("sibling.txt");\n')
            tests = repo / "admin" / "rust" / "cratea" / "tests"
            tests.mkdir()
            (tests / "runtime.rs").write_text('fn x() { let _ = root.join("scripts/untracked.py"); }\n', encoding="utf-8")
            rc, out = _run(repo)
            self.assertEqual(rc, 1, out)
            self.assertIn("runtime input bypasses repo_test_file!", out)

    def test_noise_previous_runtime_path_bypass_is_red(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _build_repo(Path(d), 'const S: &str = include_str!("sibling.txt");\n')
            source = repo / "admin" / "rust" / "cratea" / "src" / "noise.rs"
            source.write_text('fn peer() { let _ = root.join("../../../scripts/noise-conformance-peer.py"); }\n', encoding="utf-8")
            rc, out = _run(repo)
            self.assertEqual(rc, 1, out)
            self.assertIn("runtime input bypasses repo_test_file!", out)

    def test_depfile_inputs_deduplicate_paths_and_exclude_git_control_files(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "repo"
            target = Path(d) / "target"
            manifest = repo / "claws" / "manifest.yml"
            manifest.parent.mkdir(parents=True)
            manifest.write_text("name: test\n", encoding="utf-8")
            for name in ("one", "two", "three"):
                depfile = target / "debug" / f"{name}.d"
                depfile.parent.mkdir(parents=True, exist_ok=True)
                depfile.write_text(
                    f"out: {manifest} {repo / '.git' / 'HEAD'} {repo / '.git' / 'packed-refs'}\n",
                    encoding="utf-8",
                )
            self.assertEqual(
                matrix.depfile_inputs(target, repo),
                {"claws/manifest.yml"},
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
