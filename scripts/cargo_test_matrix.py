#!/usr/bin/env python3
"""The one Cargo test surface shared by Backend CI and consumption coverage.

The matrix is derived from Cargo metadata and manifests; workflows must not keep
their own package, excluded-workspace, or required-feature lists. ``--derive``
uses a fresh target directory so depfiles describe this commit, never a warm
build's historical inputs. Its output is a deduplicated set of repository paths:
coverage is defined over inputs/files, not historical source occurrence counts.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "admin" / "rust"


@dataclass(frozen=True)
class Row:
    name: str
    manifest: Path | None
    features: tuple[str, ...] = ()
    package: str | None = None


def cargo_metadata() -> dict:
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=RUST, check=True, capture_output=True, text=True,
    )
    return json.loads(result.stdout)


def matrix() -> list[Row]:
    """Derive every compile surface Backend CI promises to cover."""
    metadata = cargo_metadata()
    root_toml = tomllib.loads((RUST / "Cargo.toml").read_text(encoding="utf-8"))
    excluded = tuple(root_toml["workspace"].get("exclude", ()))
    rows = [Row("workspace", None)]
    rows.extend(Row(f"excluded:{path}", RUST / path / "Cargo.toml") for path in excluded)
    feature_rows = [
        Row(f"feature:{package['name']}:{feature}", None, (feature,), package["name"])
        for package in metadata["packages"]
        for feature in package["features"]
        if feature != "default"
    ]
    rows.extend(sorted(feature_rows, key=lambda row: row.name))
    manifests = [Path(package["manifest_path"]) for package in metadata["packages"]]
    manifests.extend(RUST / path / "Cargo.toml" for path in excluded)
    for manifest in sorted(set(manifests)):
        package = tomllib.loads(manifest.read_text(encoding="utf-8"))
        for target_kind in ("bin", "example", "test", "bench"):
            for target in package.get(target_kind, []):
                required = tuple(target.get("required-features", ()))
                if required:
                    rows.append(Row(f"required:{manifest.parent.name}:{target['name']}", manifest, required))
    return rows


def command(row: Row) -> list[str]:
    if row.package:
        return [
            "cargo", "check", "--locked", "--package", row.package,
            "--all-targets", "--features", ",".join(row.features),
        ]
    args = ["cargo", "test", "--locked"]
    if row.manifest is None:
        args.append("--workspace")
    else:
        args.extend(["--manifest-path", str(row.manifest)])
    if row.features:
        args.extend(["--features", ",".join(row.features)])
    return [*args, "--no-run"]


def fresh_target() -> Path:
    target = Path(tempfile.mkdtemp(prefix="theyos-consumption-target-"))
    os.environ.setdefault("CLAWS_CATALOG_JSON", str(target / "claws-catalog.json"))
    os.environ["CARGO_TARGET_DIR"] = str(target)
    return target


def is_versionable_repo_path(path: str) -> bool:
    """Exclude Git's mutable control files from the PR input projection."""
    return path != ".git" and not path.startswith(".git/")


def depfile_inputs(target: Path, repo_root: Path = ROOT) -> set[str]:
    """Return the deduplicated repository input paths from fresh depfiles."""
    repo_root = repo_root.resolve()
    inputs: set[str] = set()
    for depfile in sorted(target.rglob("*.d")):
        try:
            text = depfile.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for token in text.replace("\\\n", " ").split():
            candidate = Path(token.rstrip(":"))
            if not candidate.is_absolute():
                continue
            try:
                repo_rel = candidate.resolve().relative_to(repo_root).as_posix()
            except ValueError:
                continue
            if is_versionable_repo_path(repo_rel):
                inputs.add(repo_rel)
    return inputs


def run_compile(emit_inputs: bool) -> int:
    target = fresh_target()
    try:
        for row in matrix():
            stream = sys.stderr if emit_inputs else sys.stdout
            print(f"::group::consumption matrix {row.name}", file=stream)
            subprocess.run(command(row), cwd=RUST, check=True)
            print("::endgroup::", file=stream)
        if emit_inputs:
            print(json.dumps(sorted(depfile_inputs(target))))
        return 0
    finally:
        shutil.rmtree(target, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--derive", action="store_true")
    parser.add_argument("--ci-compile", action="store_true")
    parser.add_argument("--print", action="store_true")
    args = parser.parse_args()
    if args.print:
        for row in matrix():
            print(json.dumps({
                "name": row.name,
                "manifest": str(row.manifest or RUST / "Cargo.toml"),
                "package": row.package,
                "features": row.features,
            }))
        return 0
    if args.derive:
        return run_compile(True)
    if args.ci_compile:
        return run_compile(False)
    parser.error("choose --derive, --ci-compile, or --print")
    return 2


if __name__ == "__main__":
    sys.exit(main())
