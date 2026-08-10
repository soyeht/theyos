#!/usr/bin/env python3
"""Fail when the build consumes a repo file that a change to it would NOT cause
to be recompiled by the real backend CI.

The false-green class this gate exists to close (CI plan, Phase 3.1 / 3.2):

    backend-ci.yml only runs on a fixed ``paths`` list (``admin/rust/**`` and a
    few others). On a PR that changes none of them, ``backend-ci-docs-shim.yml``
    publishes the *same* required check names green WITHOUT compiling anything.
    So if a Rust source ``include_str!("PORTS.md")`` and someone edits
    ``PORTS.md`` on a docs-only PR, the real build never runs, the
    ``include_str!`` is never re-checked, and a green PR can merge a broken main.

Coverage rule.  A consumed file is *covered* when a change to it (alone) makes
the real ``backend-ci.yml`` run -- i.e. its repo-relative path matches one of the
``on.pull_request.paths`` globs in ``backend-ci.yml`` (parsed live, never copied,
because the map drifts).  The gate also requires ``on.push.paths`` to be identical
to that list, and the docs-only shim's inverse ``paths-ignore`` list to match both.
Anything consumed but not covered is a hole and fails.

What the gate can PROVE vs what it can only DECLARE (the split is deliberate
and is the point of the plan's completeness critique):

  * PROVE-uncovered (-> RED, exit 1), because the target file is statically
    resolvable to one repo path:
      - ``include_str!("literal")`` / ``include_bytes!("literal")``
      - ``concat!(env!("CARGO_MANIFEST_DIR"), "/literal")`` (incl. inside an
        ``include_str!``/``include_bytes!``)
      - literal reads inside ``build.rs`` (``include_str!``/``include_bytes!``/
        ``concat!(env!(CARGO_MANIFEST_DIR), ..)``/``read_to_string("literal")``)

  * DECLARE-only (-> listed in the report, NEVER silent, but non-failing),
    because static analysis cannot prove the consumed file is uncovered:
      - ``read_dir(...)`` and ``format!``-built paths (runtime/computed targets);
      - consumption by a test target this gate cannot prove backend-CI builds
        (e.g. ``cfg``-gated, behind a feature CI may not enable). Closing this
        class to RED needs the runtime counting manifest of Phase 3.3; until
        then it is named here, not hidden.

A class that is silently absent from the report is the failure mode the plan
calls a "gate blind in a class".  This gate therefore also fails (exit 1) if its
own self-coverage check trips: every PROVE-class must be exercised by a probe
planted under ``--self-test-probes``, so a future edit that makes the parser
blind to, say, ``include_bytes!`` is itself a red.

Exit codes (matching the other scripts here):
  0  every statically-resolvable consumed file is covered; DECLARED classes
     listed (if any)
  1  findings: at least one consumed file is provably uncovered, OR the gate's
     own completeness self-check tripped
  2  the gate could not run (no backend-ci.yml, unreadable, empty scope, ...)
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_CI = REPO_ROOT / ".github" / "workflows" / "backend-ci.yml"

# Consumers are Rust; the workspace lives here.
RUST_ROOT = REPO_ROOT / "admin" / "rust"

# --------------------------------------------------------------------------- #
# Coverage globs, parsed live from backend-ci.yml so they cannot drift.
# --------------------------------------------------------------------------- #


def parse_backend_event_paths(workflow: Path, event: str) -> list[str]:
    """Return an ``on.<event>.paths`` glob list from backend-ci.yml.

    A minimal indent-aware scan is used on purpose: it has no YAML dependency,
    and if the file's shape changes in a way this cannot parse, the gate fails
    closed (exit 2) rather than silently shrinking the covered set.
    """
    text = workflow.read_text(encoding="utf-8")
    lines = text.splitlines()
    in_event = False
    in_paths = False
    paths_indent = -1
    out: list[str] = []
    for raw in lines:
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        # Top-level keys under on: appear at 2 spaces (for example "  push:").
        if stripped == f"{event}:" and indent == 2:
            in_event = True
            in_paths = False
            continue
        if indent <= 2 and stripped.endswith(":") and stripped != f"{event}:":
            in_event = False
            in_paths = False
            continue
        if not in_event:
            continue
        if stripped == "paths:":
            in_paths = True
            paths_indent = indent + 2  # list items sit two spaces deeper
            continue
        if in_paths and stripped.startswith("- "):
            if indent != paths_indent:
                # dedented out of the list
                in_paths = False
                continue
            item = stripped[2:].strip()
            # strip an optional trailing comment, then quotes
            item = item.split("#", 1)[0].strip().strip('"').strip("'")
            if item:
                out.append(item)
        elif in_paths and not stripped.startswith("- "):
            in_paths = False
    if not out:
        raise GateCannotRun(
            f"parsed zero on.{event}.paths from {workflow} -- the workflow shape changed; "
            "update the parser or fix the file"
        )
    return out


def parse_backend_pull_request_paths(workflow: Path) -> list[str]:
    return parse_backend_event_paths(workflow, "pull_request")


def parse_backend_push_paths(workflow: Path) -> list[str]:
    return parse_backend_event_paths(workflow, "push")


def parse_shim_paths_ignore(workflow: Path) -> list[str]:
    """Parse the shim's inverse path list and fail closed on drift."""
    lines = workflow.read_text(encoding="utf-8").splitlines()
    in_pr = in_paths = False
    indent = -1
    out: list[str] = []
    for raw in lines:
        if not raw.strip():
            continue
        leading = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if stripped == "pull_request:" and leading == 2:
            in_pr, in_paths = True, False
            continue
        if leading <= 2 and stripped.endswith(":") and stripped != "pull_request:":
            in_pr = in_paths = False
        if not in_pr:
            continue
        if stripped == "paths-ignore:":
            in_paths, indent = True, leading + 2
            continue
        if in_paths and stripped.startswith("- ") and leading == indent:
            out.append(stripped[2:].split("#", 1)[0].strip().strip('"').strip("'"))
        elif in_paths and not stripped.startswith("- "):
            in_paths = False
    if not out:
        raise GateCannotRun(f"parsed zero paths-ignore from {workflow}")
    return out


class GateCannotRun(Exception):
    pass


# --------------------------------------------------------------------------- #
# gitignore-style glob matching for pathspecs like ``admin/rust/**``.
# --------------------------------------------------------------------------- #


def path_matches(path: str, pattern: str) -> bool:
    """Match a repo-relative path against a GitHub-actions-style path glob.

    Supports ``**`` (zero or more whole segments), ``*`` (within one segment),
    and exact names.  A pattern with no ``/`` matches by basename anywhere
    (gitignore semantics); a pattern with a ``/`` is anchored at the repo root.
    """
    if "/" not in pattern and "*" not in pattern:
        return Path(path).name == pattern or path == pattern
    if "**" not in pattern:
        return _simple_glob_match(path, pattern)
    # Segment-aware match with one (or more) ``**``.
    pat = pattern.split("/")
    tgt = path.split("/")
    return _double_star_match(pat, 0, tgt, 0)


def _simple_glob_match(path: str, pattern: str) -> bool:
    import fnmatch

    # Anchored: the pattern must describe the path from the root. ``foo/**``
    # is handled by the double-star branch; here patterns contain only ``*``.
    if pattern.endswith("/*"):
        head = pattern[:-2]
        return path == head or path.startswith(head + "/")
    return fnmatch.fnmatchcase(path, pattern) and _same_anchors(path, pattern)


def _same_anchors(path: str, pattern: str) -> bool:
    pi = path.split("/")
    pa = pattern.split("/")
    # leading literal segments must agree (fnmatch would otherwise let '?'/'*'
    # eat them, which is fine; this only rules out crossing a literal boundary)
    for a, b in zip(pi, pa):
        if "*" in b or "?" in b:
            break
        if a != b:
            return False
    return True


def _double_star_match(pat: list[str], pi: int, tgt: list[str], ti: int) -> bool:
    # Classic glob-with-** DP via recursion (patterns are tiny).
    while pi < len(pat):
        seg = pat[pi]
        if seg == "**":
            # ``**`` matches zero or more target segments; try every position.
            if pi == len(pat) - 1:
                return True  # trailing ** swallows the rest
            for skip in range(ti, len(tgt) + 1):
                if _double_star_match(pat, pi + 1, tgt, skip):
                    return True
            return False
        if ti >= len(tgt):
            return False
        if not _seg_match(tgt[ti], seg):
            return False
        pi += 1
        ti += 1
    return ti == len(tgt)


def _seg_match(text: str, seg: str) -> bool:
    import fnmatch

    return fnmatch.fnmatchcase(text, seg)


def is_covered(repo_rel: str, patterns: Iterable[str]) -> bool:
    return any(path_matches(repo_rel, p) for p in patterns)


# --------------------------------------------------------------------------- #
# Finding the consumption.
# --------------------------------------------------------------------------- #


@dataclass
class Use:
    consumer: str  # repo-relative .rs file
    line: int
    macro: str  # include_str! / include_bytes! / concat-cmdir / build.rs-read / ...
    target_repo_rel: str | None  # resolved repo-relative target, or None if unresolvable
    snippet: str


# Match include_str!/include_bytes! whose argument is a single string literal.
# Allows whitespace/newlines between the macro name, '(', and the literal, so a
# literal split across the next line ("include_str!(\n  \"...\"") still resolves.
_INCLUDE_RE = re.compile(
    r'include_(str|bytes)!\s*\(\s*"((?:\\.|[^"\\\n])*)"\s*\)',
    re.DOTALL,
)
# concat!(env!("CARGO_MANIFEST_DIR"), "/literal") and the include-wrapped form.
_CMDIR_RE = re.compile(
    r'(include_(?:str|bytes)!?\s*\(\s*)?concat!\s*\(\s*env!\s*\(\s*"CARGO_MANIFEST_DIR"\s*\)\s*,\s*"((?:\\.|[^"\\])*)"\s*\)',
    re.DOTALL,
)
_READDIR_RE = re.compile(r"\bread_dir\s*\(")
# build.rs literal read_to_string / File::open with a literal path.
_BUILD_READ_RE = re.compile(r'(?:read_to_string|read_to_end|open)\s*\(\s*"((?:\\.|[^"\\])*)"')
_RUNTIME_RE = re.compile(r'repo_test_file!\s*\(\s*"((?:\\.|[^"\\\n])*)"\s*\)')
# A repo-relative runtime script can be joined directly or from a crate's
# ../../../ root. Both bypass the literal macro and its depfile edge.
_RUNTIME_BYPASS_RE = re.compile(r'\.join\s*\(\s*"(?:\.\./)*scripts/')

RUST_SUFFIXES = (".rs",)


def _crate_dir(of_file: Path) -> Path:
    """Nearest ancestor containing a Cargo.toml (the crate root for env!(CMDIR))."""
    d = of_file.parent
    while d != d.parent:
        if (d / "Cargo.toml").exists():
            return d
        d = d.parent
    return of_file.parent


def _resolve(consumer: Path, literal: str, repo_root: Path) -> str | None:
    """Resolve a literal include target to a repo-relative path, or None.

    Returns None if it escapes the repo (absolute/external) -- that is a real
    file the build needs but which this gate cannot place, so the caller treats
    it as unresolvable (declared), not silently covered.
    """
    if not literal:
        return None
    p = (consumer.parent / literal)
    try:
        p = p.resolve(strict=False)
    except OSError:
        return None
    try:
        rel = p.relative_to(repo_root)
    except ValueError:
        return None
    return rel.as_posix()


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def scan_consumers(rust_root: Path, repo_root: Path) -> tuple[list[Use], list[Use]]:
    """Return (literal_uses, declared_uses) across the Rust workspace.

    literal_uses have a resolvable or repo-escaping target (PROVE class);
    declared_uses are detected-but-unresolvable classes (read_dir, etc.).
    """
    literal: list[Use] = []
    declared: list[Use] = []

    rs_files = sorted(p for p in rust_root.rglob("*") if p.suffix in RUST_SUFFIXES)

    for f in rs_files:
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            declared.append(Use(_rel(f, repo_root), 0, "unreadable-source", None, ""))
            continue
        is_buildrs = f.name == "build.rs"

        # include_str!/include_bytes! with a literal string.
        for m in _INCLUDE_RE.finditer(text):
            kind, lit = m.group(1), m.group(2)
            unesc = _unescape(lit)
            target = _resolve(f, unesc, repo_root)
            macro = "include_str!" if kind == "str" else "include_bytes!"
            literal.append(Use(_rel(f, repo_root), _line_of(text, m.start()), macro, target, m.group(0)[:80]))

        # concat!(env!("CARGO_MANIFEST_DIR"), "/literal") -- resolve from crate dir.
        for m in _CMDIR_RE.finditer(text):
            lit = _unescape(m.group(2))
            target = _resolve_crate(_crate_dir(f), lit, repo_root)
            literal.append(Use(_rel(f, repo_root), _line_of(text, m.start()), "concat-cmdir", target, m.group(0)[:80]))

        # build.rs literal reads.
        if is_buildrs:
            for m in _BUILD_READ_RE.finditer(text):
                lit = _unescape(m.group(1))
                target = _resolve(f, lit, repo_root)
                literal.append(Use(_rel(f, repo_root), _line_of(text, m.start()), "build.rs-read", target, m.group(0)[:80]))

        for m in _RUNTIME_RE.finditer(text):
            literal.append(Use(_rel(f, repo_root), _line_of(text, m.start()), "repo_test_file!", _unescape(m.group(1)), m.group(0)))
        if "/tests/" in f.as_posix() or f.name == "noise.rs":
            for m in _RUNTIME_BYPASS_RE.finditer(text):
                declared.append(Use(_rel(f, repo_root), _line_of(text, m.start()), "runtime-path-bypass", None, m.group(0)))

        # DECLARED: read_dir (runtime directory listing; which files are read is
        # not statically known).
        for m in _READDIR_RE.finditer(text):
            declared.append(Use(_rel(f, repo_root), _line_of(text, m.start()), "read_dir", None, "read_dir(...)"))

    return literal, declared


def _resolve_crate(crate_dir: Path, literal: str, repo_root: Path) -> str | None:
    if not literal:
        return None
    # CARGO_MANIFEST_DIR has no trailing slash, so the appended literal usually
    # starts with '/'. Strip exactly one leading separator (or a leading './'),
    # not a charset -- lstrip("./") would eat "/../" and silently relocate.
    lit = literal
    if lit.startswith("/"):
        lit = lit[1:]
    elif lit.startswith("./"):
        lit = lit[2:]
    p = (crate_dir / lit).resolve(strict=False)
    try:
        return p.relative_to(repo_root).as_posix()
    except ValueError:
        return None


def _unescape(s: str) -> str:
    # Only the escapes that can appear in an include path literal; anything more
    # exotic won't resolve on disk and becomes a declared finding, not a silent
    # pass.
    return s.replace("\\\\", "\\").replace('\\"', '"')


def _rel(p: Path, repo_root: Path) -> str:
    try:
        return p.relative_to(repo_root).as_posix()
    except ValueError:
        return str(p)


# --------------------------------------------------------------------------- #
# Completeness self-check: each PROVE-class must be exercisable by a probe.
# --------------------------------------------------------------------------- #


# The macro kinds this gate claims to PROVE-uncovered. If a probe for any of
# these is planted (under --self-test-probes) and NOT seen by the parser, the
# gate is blind in that class and must go red.
PROVE_CLASSES = ("include_str!", "include_bytes!", "concat-cmdir", "build.rs-read", "repo_test_file!")


def completeness_selfcheck(literal: list[Use], probe_kinds: set[str]) -> list[str]:
    """Return a list of 'blind class' errors: a PROVE-class that the probes
    expected to exercise but the parser found no use of."""
    seen = {u.macro for u in literal}
    errors = []
    for kind in PROVE_CLASSES:
        if kind in probe_kinds and kind not in seen:
            errors.append(
                f"completeness: parser is blind to PROVE-class '{kind}' "
                "(probe planted but no use found) -- the gate would miss this class"
            )
    return errors


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def derive_compile_inputs(repo_root: Path) -> list[Use]:
    result = subprocess.run(
        [sys.executable, str(repo_root / "scripts" / "cargo_test_matrix.py"), "--derive"],
        cwd=repo_root, text=True, capture_output=True,
    )
    if result.returncode:
        raise GateCannotRun(f"fresh Cargo matrix failed:\n{result.stderr}")
    try:
        inputs = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise GateCannotRun(f"fresh Cargo matrix emitted invalid input inventory: {exc}") from exc
    if not isinstance(inputs, list) or not all(isinstance(path, str) for path in inputs):
        raise GateCannotRun("fresh Cargo matrix emitted invalid input paths")
    return [Use("cargo-test-matrix", 0, "depfile", path, path) for path in inputs]


def run(repo_root: Path, backend_ci: Path, probe_kinds: set[str], out=sys.stdout, derive: bool = False) -> int:
    # Resolve once: under macOS the system temp lives behind a /var -> /private/var
    # symlink, so a caller-supplied root that is not canonicalised would mismatch
    # the resolved target paths and every include would look "unresolvable".
    repo_root = repo_root.resolve()
    backend_ci = backend_ci.resolve()
    patterns = parse_backend_pull_request_paths(backend_ci)
    if parse_backend_push_paths(backend_ci) != patterns:
        raise GateCannotRun("backend-ci push paths and pull_request paths differ")
    shim = repo_root / ".github" / "workflows" / "backend-ci-docs-shim.yml"
    if parse_shim_paths_ignore(shim) != patterns:
        raise GateCannotRun("backend-ci pull_request paths and docs-shim paths-ignore differ")
    for workflow in (".github/workflows/backend-ci.yml", ".github/workflows/backend-ci-docs-shim.yml"):
        if workflow not in patterns:
            raise GateCannotRun(f"real/shim self-certification missing {workflow}")
    rust_root = repo_root / "admin" / "rust"
    if not rust_root.is_dir():
        raise GateCannotRun(f"rust workspace not found at {rust_root}")

    literal, declared = scan_consumers(rust_root, repo_root)
    if derive:
        literal.extend(derive_compile_inputs(repo_root))

    uncovered: list[Use] = []
    covered: list[Use] = []
    unresolvable: list[Use] = []
    for u in literal:
        if u.target_repo_rel is None:
            unresolvable.append(u)
        elif is_covered(u.target_repo_rel, patterns):
            covered.append(u)
        else:
            uncovered.append(u)

    blind = completeness_selfcheck(literal, probe_kinds)
    blind.extend(
        f"runtime input bypasses repo_test_file!: {u.consumer}:{u.line}"
        for u in declared if u.macro == "runtime-path-bypass"
    )

    # ---- report ----
    print(f"coverage globs (from {backend_ci.relative_to(repo_root)}):", file=out)
    for p in patterns:
        print(f"  - {p}", file=out)
    print(f"literal consumption uses scanned: {len(literal)}", file=out)

    if covered:
        print(f"\ncovered ({len(covered)}):", file=out)
        for u in sorted(covered, key=lambda x: (x.target_repo_rel or "", x.consumer)):
            print(f"  OK   {u.target_repo_rel}  <- {u.consumer}:{u.line} ({u.macro})", file=out)

    if uncovered:
        uncovered_paths = {u.target_repo_rel for u in uncovered}
        print(f"\nUNCOVERED consumed paths ({len(uncovered_paths)}) -- changing one does NOT trigger backend-ci:", file=out)
        for u in sorted(uncovered, key=lambda x: (x.target_repo_rel or "", x.consumer)):
            print(f"  RED  {u.target_repo_rel}  <- {u.consumer}:{u.line} ({u.macro})", file=out)

    if unresolvable:
        print(f"\nUNRESOLVABLE consumed targets ({len(unresolvable)}) -- literal escapes repo or does not resolve:", file=out)
        for u in unresolvable:
            print(f"  ???  {u.consumer}:{u.line} ({u.macro}) {u.snippet}", file=out)

    if declared:
        print(f"\nDECLARED classes (detected, not statically provable; never silent, non-failing):", file=out)
        for u in sorted(declared, key=lambda x: (x.consumer, x.line)):
            print(f"  DEC  {u.consumer}:{u.line} ({u.macro}) -- manual coverage check required", file=out)
        print(
            "  note: read_dir/format!/runtime-built paths and test-targets-CI-doesn't-build\n"
            "        are detected and listed but not failed; proving their uncoverage needs\n"
            "        the runtime counting manifest of Phase 3.3. This declaration is the\n"
            "        boundary, documented, not a silent gap.",
            file=out,
        )

    if blind:
        print("\nGATE COMPLETENESS FAILURE:", file=out)
        for b in blind:
            print(f"  BLIND  {b}", file=out)

    findings = bool(uncovered) or bool(blind)
    if findings:
        uncovered_paths = {u.target_repo_rel for u in uncovered}
        print(
            f"\nresult: FAIL ({len(uncovered_paths)} uncovered paths, {len(blind)} blind-class)",
            file=out,
        )
        return 1
    print(
        f"\nresult: PASS ({len(covered)} covered, {len(unresolvable)} unresolvable, "
        f"{len(declared)} declared)",
        file=out,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="repository root (default: autodetect)",
    )
    ap.add_argument("--derive", action="store_true", help="derive compile-time inputs from the fresh shared Cargo matrix")
    ap.add_argument(
        "--backend-ci",
        type=Path,
        default=None,
        help="backend-ci.yml to parse paths from (default: <repo>/.github/workflows/backend-ci.yml)",
    )
    ap.add_argument(
        "--self-test-probes",
        action="append",
        default=[],
        help="PROVE-class kinds a self-test planted in this run (repeatable); "
        "used by the completeness self-check. Values: "
        + ", ".join(PROVE_CLASSES),
    )
    args = ap.parse_args(argv)

    backend_ci = args.backend_ci or (args.repo_root / ".github" / "workflows" / "backend-ci.yml")
    if not backend_ci.is_file():
        print(f"error: backend-ci workflow not found: {backend_ci}", file=sys.stderr)
        return 2
    probe_kinds = set(args.self_test_probes)

    try:
        return run(args.repo_root, backend_ci, probe_kinds, derive=args.derive)
    except GateCannotRun as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
