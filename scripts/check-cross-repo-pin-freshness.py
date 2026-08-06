#!/usr/bin/env python3
"""Fail when a consumer repo's pin on theyos has stopped telling the truth."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = "admin/contracts/cross-repo/v1/ios_ffi_boundary_v1.json"
DEFAULT_TARGET_REV = "origin/main"
SCHEMA = "cross-repo-ffi-boundary-v1"

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_MALFORMED = 2
EXIT_CANNOT_EVALUATE = 3

SECONDS_PER_DAY = 86400
REV_RE = re.compile(r"^[0-9a-f]{40}$")

# Every syntactic form that puts an item on the uniffi-exported surface.
# ONE token list feeds BOTH consumers -- the tree sweep and the per-file
# extractor. If the sweep looked for less than the extractor reads, it would
# report "no surface here" about a file full of surface.
#
# The two spellings are NOT interchangeable. `git grep -E` is POSIX ERE: it
# rejects `(?:` outright, and it accepts `\b` while silently matching NOTHING
# with it. A sweep that finds nothing is indistinguishable from a clean tree,
# which is why check_surface_sweep treats an empty result as a failure.
UNIFFI_SURFACE_TOKENS = (
    "setup_scaffolding",
    "export",
    "constructor",
    "method",
    "Record",
    "Enum",
    "Object",
    "Error",
    "Interface",
    "custom_type",
)
UNIFFI_MARKER_RE = re.compile(r"uniffi::(?:" + "|".join(UNIFFI_SURFACE_TOKENS) + r")\b")
UNIFFI_SWEEP_ERE = "uniffi::(" + "|".join(UNIFFI_SURFACE_TOKENS) + ")"

# ── Policy: how stale a pin may be, and why these numbers ────────────────────
#
# MEASURED 2026-08-06 against origin/main and the consumer's own pin history.
# Both bounds are derived from observed behaviour of this boundary, not chosen
# for roundness. If you change one, change the reasoning with it.
#
# MAX_DAYS_BEHIND = 14
#   Derived from the consumer pin that WAS being maintained
#   (scripts/cross-repo-contract.sha): 13 bumps between 2026-06-22 and
#   2026-07-14, and the largest gap between two consecutive bumps in that
#   healthy stretch was 14 days (2026-06-25 -> 2026-07-09). So 14 days is the
#   observed upper edge of normal maintenance on this boundary. Every pin that
#   actually rotted sits above it: 43 days (the FFI rev), 23 days and 21 days
#   (the two fixture revs). The line therefore separates observed-healthy from
#   observed-rotted using this repo's own history, with no invented margin.
#
#   Days, not commits, is the primary sensor on purpose. "858 commits behind"
#   is a number nobody can size; "43 days behind" is a number a human acts on.
#
# MAX_COMMITS_BEHIND = 400
#   A burst backstop, not the primary bound. main runs a volatile 13-26
#   commits/day (1159 in 90 days, 597 in 30, 205 in one 14-day window, 181 in
#   one 7-day window). A commit bound derived as "14 days x rate" would itself
#   rot as the rate moves, so this one is deliberately loose: ~2x the observed
#   14-day volume. It fires only when a calendar-fresh pin is nonetheless
#   sitting behind an abnormal burst of work. It does NOT catch the two fixture
#   pins (248 and 219 behind) -- MAX_DAYS_BEHIND does. That asymmetry is the
#   design, not a gap.
#
# MAX_PIN_SPREAD_DAYS = 7
#   When more than one pin exists, they should come from ONE boundary decision.
#   In the maintained stretch, pins moved in clusters <=2 days wide
#   (06-22/06-23, 06-25, 07-09/07-10, 07-14). 7 days is generous against that
#   and still names today's real disagreement: the three live pins span 22 days
#   (2026-06-24, 2026-07-14, 2026-07-16), i.e. the app ships built against
#   three different notions of what theyos is.
#
# THRESHOLD_REVIEW_BY
#   The numbers above are themselves numbers nobody re-evaluates -- the very
#   failure this gate exists to stop. So they expire. Past this date the gate
#   fails until someone re-runs the measurement and either confirms or moves
#   them. A self-expiring threshold is a mechanism; a comment saying "revisit
#   periodically" is a wish.
MAX_DAYS_BEHIND = 14
MAX_COMMITS_BEHIND = 400
MAX_PIN_SPREAD_DAYS = 7
THRESHOLD_MEASURED_ON = "2026-08-06"
THRESHOLD_REVIEW_BY = "2027-02-06"
THRESHOLD_REMEASURE_HINT = (
    "re-measure with: git log --format=%ci <consumer>/<pin-file> (bump cadence) "
    "and git rev-list --count --since=<N>' days ago' origin/main (commit rate)"
)


class CannotEvaluate(Exception):
    """The gate could not observe what it needs. Never a pass."""


class Malformed(Exception):
    """An input the gate must read is unreadable or unparseable. Never a pass."""


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    unchecked: list[str] = field(default_factory=list)

    def fail(self, message: str) -> None:
        self.errors.append(message)

    def note(self, message: str) -> None:
        self.notes.append(message)

    def skip(self, message: str) -> None:
        self.unchecked.append(message)


# ── git ──────────────────────────────────────────────────────────────────────


def git(*args: str, allow_codes: tuple[int, ...] = (0,)) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ("git", *args),
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as error:
        raise CannotEvaluate(f"could not run git: {error.__class__.__name__}") from error
    if proc.returncode not in allow_codes:
        raise CannotEvaluate(f"git {args[0]} failed (exit {proc.returncode})")
    return proc.returncode, proc.stdout


def resolve_commit(rev: str) -> str:
    code, out = git("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}", allow_codes=(0, 1))
    resolved = out.strip()
    if code != 0 or not REV_RE.match(resolved):
        raise CannotEvaluate(
            f"rev {shorten(rev)} is not present in this checkout "
            "(CI must clone with full history: fetch-depth: 0)"
        )
    return resolved


def commit_timestamp(rev: str) -> int:
    _, out = git("show", "-s", "--format=%ct", rev)
    try:
        return int(out.strip())
    except ValueError as error:
        raise CannotEvaluate(f"could not read commit time of {shorten(rev)}") from error


def is_ancestor(ancestor: str, descendant: str) -> bool:
    code, _ = git("merge-base", "--is-ancestor", ancestor, descendant, allow_codes=(0, 1))
    return code == 0


def commits_between(ancestor: str, descendant: str) -> int:
    _, out = git("rev-list", "--count", f"{ancestor}..{descendant}")
    try:
        return int(out.strip())
    except ValueError as error:
        raise CannotEvaluate("could not count commits between revs") from error


def blob_at(rev: str, path: str) -> str | None:
    """File content at rev, or None when the path does not exist there."""
    code, out = git("show", f"{rev}:{path}", allow_codes=(0, 128))
    if code != 0:
        return None
    return out


def surface_files_at(rev: str) -> list[str]:
    """Sweep the tree at rev for every .rs file carrying a uniffi marker."""
    code, out = git(
        "grep", "-l", "-E", UNIFFI_SWEEP_ERE, rev, "--", "*.rs",
        allow_codes=(0, 1),
    )
    if code == 1:
        return []
    prefix = f"{rev}:"
    found = []
    for line in out.splitlines():
        if not line.startswith(prefix):
            raise CannotEvaluate("git grep produced an unrecognised line format")
        found.append(line[len(prefix):])
    return sorted(found)


def shorten(rev: str) -> str:
    return rev[:12] if REV_RE.match(rev) else rev


# ── uniffi surface extraction ────────────────────────────────────────────────
#
# Built against the real bytes of admin/rust/claw-share-bridge-rs/src/lib.rs,
# not against an idea of what uniffi code looks like. The forms that actually
# occur there:
#
#   uniffi::setup_scaffolding!();
#   #[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
#   #[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#   #[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#   #[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#   #[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
#
# attached to `pub enum`, `pub struct`, `impl NAME`, and free `pub async fn`.
# The derive attribute appears both before and after plain #[derive(...)], and
# doc comments appear above and between attributes -- so attributes are
# collected as a run and doc comments do not break the run.
#
# What is deliberately NOT in the extracted surface: private struct fields on a
# uniffi::Object (they are not crossing the boundary), function bodies, and any
# item without a uniffi marker. The output is the set of things a Swift caller
# can name. That is the property "did the boundary move?" is written in.

ITEM_RE = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?P<kind>struct|enum|impl|fn|async\s+fn)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
FIELD_RE = re.compile(r"^\s*pub\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<ty>.+?)\s*,?\s*$")
VARIANT_RE = re.compile(r"^\s*(?P<name>[A-Z][A-Za-z0-9_]*)\s*(?P<payload>\(.*?\)|\{.*)?\s*,?\s*$")
METHOD_RE = re.compile(r"^\s*pub\s+(?:async\s+)?fn\s+[A-Za-z_][A-Za-z0-9_]*")


def _read_attribute(lines: list[str], index: int) -> tuple[str, int]:
    """Consume one (possibly multi-line) attribute starting at index."""
    depth = 0
    parts: list[str] = []
    while index < len(lines):
        line = lines[index]
        parts.append(line.strip())
        depth += line.count("[") - line.count("]")
        index += 1
        if depth <= 0:
            break
    else:
        raise Malformed("unterminated attribute in surface file")
    return " ".join(parts), index


def _read_block(lines: list[str], index: int) -> tuple[list[str], int]:
    """Consume a `{ ... }` block whose opening brace is on lines[index].

    Returns the lines strictly inside the block at depth 1 and the index just
    past the closing brace. An unbalanced block is Malformed, never an empty
    body -- a truncated file must not read as "this type has no fields".
    """
    depth = 0
    body: list[str] = []
    opened = False
    while index < len(lines):
        line = lines[index]
        before = depth
        depth += line.count("{") - line.count("}")
        if not opened and "{" in line:
            opened = True
        elif opened and before == 1:
            body.append(line)
        index += 1
        if opened and depth <= 0:
            return body, index
    raise Malformed("unterminated block in surface file")


def _read_signature(lines: list[str], index: int) -> tuple[str, int]:
    """Consume a whole `fn` signature, which may span several lines.

    Stopping at the first line would silently drop every parameter of a
    multi-line signature -- the extractor would return LESS rather than error,
    and a parameter change on the boundary would read as no change at all.
    """
    parts: list[str] = []
    parens = 0
    while index < len(lines):
        code = lines[index].split("//")[0]
        parts.append(code.strip())
        parens += code.count("(") - code.count(")")
        index += 1
        if parens <= 0 and ("{" in code or code.rstrip().endswith(";")):
            return _normalise(" ".join(p for p in parts if p).split("{")[0]), index
    raise Malformed("unterminated fn signature in surface file")


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip()).rstrip("{").strip()


def extract_surface(source: str) -> list[str]:
    """Canonical, order-independent list of uniffi-exported surface items."""
    lines = source.splitlines()
    items: list[str] = []
    pending: list[str] = []
    index = 0
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()

        if stripped.startswith("#["):
            attr, index = _read_attribute(lines, index)
            pending.append(attr)
            continue

        if not stripped or stripped.startswith("//"):
            index += 1
            continue

        attrs = " ".join(pending)
        pending = []

        if UNIFFI_MARKER_RE.search(stripped) and "!" in stripped:
            items.append("scaffolding")
            index += 1
            continue

        match = ITEM_RE.match(raw)
        if not match or not UNIFFI_MARKER_RE.search(attrs):
            index += 1
            continue

        kind = re.sub(r"\s+", " ", match.group("kind"))
        name = match.group("name")

        if "uniffi::Record" in attrs and kind == "struct":
            body, index = _read_block(lines, index)
            items.append(f"record {name}")
            for line in body:
                field_match = FIELD_RE.match(line)
                if field_match:
                    items.append(f"record {name}.{field_match.group('name')}: {_normalise(field_match.group('ty'))}")
            continue

        if ("uniffi::Enum" in attrs or "uniffi::Error" in attrs) and kind == "enum":
            label = "error" if "uniffi::Error" in attrs else "enum"
            body, index = _read_block(lines, index)
            items.append(f"{label} {name}")
            for line in body:
                text = line.strip()
                if not text or text.startswith("//") or text.startswith("#["):
                    continue
                variant_match = VARIANT_RE.match(text)
                if variant_match:
                    payload = _normalise(variant_match.group("payload") or "")
                    items.append(f"{label} {name}::{variant_match.group('name')}{payload}")
            continue

        if "uniffi::Object" in attrs or "uniffi::Interface" in attrs:
            items.append(f"object {name}")
            index += 1
            continue

        if "uniffi::export" in attrs and kind == "impl":
            body, index = _read_block(lines, index)
            cursor = 0
            while cursor < len(body):
                if METHOD_RE.match(body[cursor]):
                    signature, cursor = _read_signature(body, cursor)
                    items.append(f"method {name}::{signature}")
                else:
                    cursor += 1
            continue

        if "uniffi::export" in attrs and kind in ("fn", "async fn"):
            signature, index = _read_signature(lines, index)
            items.append(f"function {signature}")
            continue

        index += 1

    return sorted(set(items))


def surface_at(rev: str, paths: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    """Extract the surface of each path at rev. Returns (surface, missing)."""
    surface: dict[str, list[str]] = {}
    missing: list[str] = []
    for path in paths:
        source = blob_at(rev, path)
        if source is None:
            missing.append(path)
            continue
        surface[path] = extract_surface(source)
    return surface, missing


# ── pin parsing ──────────────────────────────────────────────────────────────


def parse_cargo_git_rev(text: str, dependency: str, label: str) -> str:
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise Malformed(f"{label} is not valid TOML") from error
    found: list[str] = []
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        entry = parsed.get(table, {})
        if not isinstance(entry, dict):
            raise Malformed(f"{label} [{table}] is not a table")
        spec = entry.get(dependency)
        if spec is None:
            continue
        if not isinstance(spec, dict) or "rev" not in spec:
            raise Malformed(f"{label} dependency {dependency} carries no git rev")
        found.append(str(spec["rev"]))
    if not found:
        raise Malformed(f"{label} declares no dependency named {dependency}")
    if len(set(found)) != 1:
        raise Malformed(f"{label} pins {dependency} at more than one rev")
    return found[0]


def parse_bare_rev(text: str, label: str) -> str:
    candidates = [
        line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")
    ]
    if len(candidates) != 1:
        raise Malformed(f"{label} must hold exactly one rev line, found {len(candidates)}")
    return candidates[0]


def parse_keyed_rev(text: str, key: str, label: str) -> str:
    found = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        if name.strip() == key:
            found.append(value.strip())
    if len(found) != 1:
        raise Malformed(f"{label} must hold exactly one {key} line, found {len(found)}")
    return found[0]


def parse_shell_assigned_rev(text: str, variable: str, label: str) -> str:
    """A rev assigned to a shell variable, e.g. `SOURCE_REV="c81144ba..."`.

    This kind exists because the pin that actually governs the compiled surface
    moved OUT of `Cargo.toml`. The consumer switched `household-rs` to a
    `path = ".vendor/theyos/..."` dependency populated by its build script, and
    the immutable revision moved into that script. A gate that only knew how to
    read `Cargo.toml` was left reading a dependency form the consumer no longer
    uses, and reported a rev 42 days stale when the live one was 6 — the failure
    mode of a gate is not only missing a defect, it is confidently measuring a
    thing that has moved.

    Quoting is optional and both quote styles are accepted, because a shell
    assignment is written by hand; anything else about the line is rejected
    rather than guessed at.
    """
    found = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        # `export FOO=...` is the same assignment; anything else before the name
        # (a function call, a conditional) is not, and must not match.
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].lstrip()
        name, _, value = stripped.partition("=")
        if name.strip() != variable:
            continue
        value = value.strip()
        # Strip ONE matching pair of quotes. An unbalanced quote is malformed
        # input, not something to normalise away.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        found.append(value)
    if len(found) != 1:
        raise Malformed(
            f"{label} must assign {variable} exactly once, found {len(found)}"
        )
    return found[0]


def read_pin(consumer_root: Path, pin: dict[str, object]) -> str:
    name = str(pin.get("name", "<unnamed>"))
    rel = pin.get("path")
    kind = pin.get("kind")
    if not isinstance(rel, str) or not rel or not isinstance(kind, str):
        raise Malformed(f"pin {name} declares no usable path/kind")
    label = f"pin {name} (<consumer>/{rel})"
    target = consumer_root / rel
    try:
        text = target.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise Malformed(f"{label} does not exist in the consumer checkout") from error
    except UnicodeDecodeError as error:
        raise Malformed(f"{label} is not valid UTF-8") from error
    except OSError as error:
        raise Malformed(f"{label} could not be read: {error.__class__.__name__}") from error

    if kind == "cargo-git-rev":
        dependency = pin.get("dependency")
        if not isinstance(dependency, str) or not dependency:
            raise Malformed(f"{label} declares kind cargo-git-rev without a dependency name")
        rev = parse_cargo_git_rev(text, dependency, label)
    elif kind == "bare-rev":
        rev = parse_bare_rev(text, label)
    elif kind == "keyed-rev":
        key = pin.get("key")
        if not isinstance(key, str) or not key:
            raise Malformed(f"{label} declares kind keyed-rev without a key")
        rev = parse_keyed_rev(text, key, label)
    elif kind == "shell-assigned-rev":
        variable = pin.get("variable")
        if not isinstance(variable, str) or not variable:
            raise Malformed(
                f"{label} declares kind shell-assigned-rev without a variable"
            )
        rev = parse_shell_assigned_rev(text, variable, label)
    else:
        raise Malformed(f"{label} declares unknown pin kind {kind}")

    if not REV_RE.match(rev):
        raise Malformed(f"{label} does not hold a 40-character lowercase hex rev")
    return rev


def consumer_dependency_names(consumer_root: Path, manifests: list[str]) -> set[str]:
    names: set[str] = set()
    for rel in manifests:
        label = f"<consumer>/{rel}"
        try:
            text = (consumer_root / rel).read_text(encoding="utf-8")
        except FileNotFoundError as error:
            raise Malformed(f"{label} does not exist in the consumer checkout") from error
        except (OSError, UnicodeDecodeError) as error:
            raise Malformed(f"{label} could not be read: {error.__class__.__name__}") from error
        try:
            parsed = tomllib.loads(text)
        except tomllib.TOMLDecodeError as error:
            raise Malformed(f"{label} is not valid TOML") from error
        for table in ("dependencies", "dev-dependencies", "build-dependencies"):
            entry = parsed.get(table, {})
            if isinstance(entry, dict):
                names.update(entry.keys())
    return names


def crate_name_for(rev: str, surface_path: str) -> str:
    """Crate that owns a surface file, read from its Cargo.toml at rev."""
    parts = Path(surface_path).parts
    if "src" not in parts:
        raise Malformed(f"surface path {surface_path} is not inside a crate src/ directory")
    crate_dir = Path(*parts[: parts.index("src")])
    manifest = blob_at(rev, str(crate_dir / "Cargo.toml"))
    if manifest is None:
        raise Malformed(f"surface path {surface_path} has no Cargo.toml at {crate_dir}")
    try:
        parsed = tomllib.loads(manifest)
    except tomllib.TOMLDecodeError as error:
        raise Malformed(f"{crate_dir}/Cargo.toml is not valid TOML") from error
    name = parsed.get("package", {}).get("name")
    if not isinstance(name, str) or not name:
        raise Malformed(f"{crate_dir}/Cargo.toml declares no package name")
    return name


# ── manifest ─────────────────────────────────────────────────────────────────


def load_manifest(path: Path) -> dict[str, object]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise Malformed("boundary manifest does not exist") from error
    except UnicodeDecodeError as error:
        raise Malformed("boundary manifest is not valid UTF-8") from error
    except OSError as error:
        raise Malformed(f"boundary manifest could not be read: {error.__class__.__name__}") from error
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as error:
        raise Malformed("boundary manifest is not valid JSON") from error
    if not isinstance(parsed, dict):
        raise Malformed("boundary manifest must be a JSON object")
    if parsed.get("schema") != SCHEMA:
        raise Malformed(f"boundary manifest schema must be {SCHEMA}")
    declared = parsed.get("surface_files")
    if not isinstance(declared, list) or not declared or not all(isinstance(p, str) and p for p in declared):
        raise Malformed("boundary manifest surface_files must be a non-empty list of paths")
    consumers = parsed.get("consumers")
    if not isinstance(consumers, list) or not consumers:
        raise Malformed("boundary manifest consumers must be a non-empty list")
    for consumer in consumers:
        if not isinstance(consumer, dict):
            raise Malformed("boundary manifest consumer entries must be objects")
        pins = consumer.get("pins")
        if not isinstance(pins, list) or not pins:
            raise Malformed("boundary manifest consumer declares no pins")
    return parsed


# ── checks ───────────────────────────────────────────────────────────────────


def check_threshold_provenance(report: Report, now: int) -> None:
    """The staleness numbers themselves expire, so they get re-measured."""
    review_by = time.mktime(time.strptime(THRESHOLD_REVIEW_BY, "%Y-%m-%d"))
    if now > review_by:
        report.fail(
            f"staleness thresholds were measured on {THRESHOLD_MEASURED_ON} and expired on "
            f"{THRESHOLD_REVIEW_BY}; re-measure and move THRESHOLD_REVIEW_BY, do not just bump it "
            f"({THRESHOLD_REMEASURE_HINT})"
        )


def check_surface_sweep(report: Report, target: str, declared: list[str]) -> None:
    """The declared surface list must equal what the tree actually carries."""
    discovered = set(surface_files_at(target))
    declared_set = set(declared)

    for path in sorted(discovered - declared_set):
        report.fail(
            f"{path} carries uniffi cross-repo surface but is not declared in the boundary "
            "manifest; declare it and decide whether every consumer must re-pin"
        )
    for path in sorted(declared_set - discovered):
        report.fail(
            f"{path} is declared as cross-repo surface but carries no uniffi markers at the "
            "target rev; the surface moved, or the sweep pattern stopped matching it"
        )
    if not discovered:
        report.fail(
            "the uniffi sweep found no surface anywhere in the tree; a search that finds "
            "nothing is a broken instrument, not a clean repo"
        )


def check_surface_extractable(report: Report, target: str, declared: list[str]) -> None:
    """A declared surface file that yields nothing is a failure, not silence."""
    surface, missing = surface_at(target, declared)
    for path in missing:
        report.fail(f"{path} is declared as cross-repo surface but does not exist at the target rev")
    for path, items in surface.items():
        if not items:
            report.fail(
                f"{path} is declared as cross-repo surface but the extractor read zero items "
                "from it; either the surface was deleted or the extractor stopped matching"
            )
        elif "scaffolding" not in items:
            report.fail(
                f"{path} carries uniffi items but no uniffi::setup_scaffolding!; the bindings "
                "for this file are not generated, so nothing here reaches a consumer"
            )


def check_surface_coverage(
    report: Report, target: str, declared: list[str], consumer_name: str, dependencies: set[str]
) -> None:
    """Every crate carrying cross-repo surface must actually be consumed."""
    for path in declared:
        if blob_at(target, path) is None:
            # Already named precisely by check_surface_extractable. Raising
            # here would abort the run and throw away every finding collected
            # so far, replacing a precise diagnosis with a generic one.
            continue
        try:
            crate = crate_name_for(target, path)
        except Malformed as error:
            report.fail(f"cannot determine which crate owns cross-repo surface {path}: {error}")
            continue
        if crate not in dependencies:
            report.fail(
                f"consumer {consumer_name} does not depend on {crate}, which carries cross-repo "
                f"FFI surface ({path}); the surface ships in theyos and reaches no consumer build"
            )


def check_pin_freshness(report: Report, pin_name: str, rev: str, target: str, now: int) -> int:
    """Ancestry plus a bounded distance in both days and commits."""
    resolved = resolve_commit(rev)
    if not is_ancestor(resolved, target):
        report.fail(
            f"pin {pin_name} at {shorten(resolved)} is not an ancestor of the target rev; it "
            "points at an abandoned or diverged branch, which is worse than merely stale"
        )
        return commit_timestamp(resolved)

    pin_ts = commit_timestamp(resolved)
    days = int((now - pin_ts) // SECONDS_PER_DAY)
    behind = commits_between(resolved, target)

    if days > MAX_DAYS_BEHIND:
        report.fail(
            f"pin {pin_name} at {shorten(resolved)} is {days} days behind (bound {MAX_DAYS_BEHIND}); "
            f"it is also {behind} commits behind"
        )
    if behind > MAX_COMMITS_BEHIND:
        report.fail(
            f"pin {pin_name} at {shorten(resolved)} is {behind} commits behind "
            f"(bound {MAX_COMMITS_BEHIND}); it is {days} days old"
        )
    if days <= MAX_DAYS_BEHIND and behind <= MAX_COMMITS_BEHIND:
        report.note(f"pin {pin_name} at {shorten(resolved)}: {days} days / {behind} commits behind")
    return pin_ts


def check_pin_agreement(report: Report, dated: list[tuple[str, str, int]]) -> None:
    """More than one pin must agree, or the gate names the disagreement."""
    if len(dated) < 2:
        return
    revs = {rev for _, rev, _ in dated}
    ordered = sorted(dated, key=lambda item: item[2])
    spread_days = int((ordered[-1][2] - ordered[0][2]) // SECONDS_PER_DAY)
    if len(revs) == 1:
        report.note(f"all {len(dated)} pins agree at {shorten(ordered[0][1])}")
        return
    detail = ", ".join(f"{name}={shorten(rev)}" for name, rev, _ in ordered)
    if spread_days > MAX_PIN_SPREAD_DAYS:
        report.fail(
            f"pins disagree across {spread_days} days (bound {MAX_PIN_SPREAD_DAYS}): {detail}; "
            "the consumer builds against more than one notion of what theyos is"
        )
    else:
        report.note(f"pins differ but within {spread_days} days: {detail}")


def check_surface_drift(
    report: Report, pin_name: str, rev: str, target: str, declared: list[str]
) -> None:
    """The check that fires regardless of distance: did the boundary move?"""
    resolved = resolve_commit(rev)
    pin_surface, pin_missing = surface_at(resolved, declared)
    head_surface, head_missing = surface_at(target, declared)

    for path in pin_missing:
        if path not in head_missing:
            report.fail(
                f"pin {pin_name} predates {path} entirely: cross-repo FFI surface was ADDED "
                f"after {shorten(resolved)} and the consumer has never seen it"
            )
    for path in head_missing:
        if path not in pin_missing:
            report.fail(
                f"pin {pin_name}: cross-repo FFI surface {path} existed at {shorten(resolved)} "
                "and is gone at the target rev; the consumer compiles against a removed surface"
            )

    for path in sorted(set(pin_surface) & set(head_surface)):
        before = set(pin_surface[path])
        after = set(head_surface[path])
        for item in sorted(after - before):
            report.fail(f"pin {pin_name}: FFI surface ADDED since the pin in {path}: {item}")
        for item in sorted(before - after):
            report.fail(f"pin {pin_name}: FFI surface REMOVED since the pin in {path}: {item}")


# ── driver ───────────────────────────────────────────────────────────────────


def run(
    manifest_path: Path,
    consumer_root: Path | None,
    target_rev: str,
    now: int,
    surface_only: bool,
) -> Report:
    report = Report()
    manifest = load_manifest(manifest_path)
    declared = [str(p) for p in manifest["surface_files"]]
    target = resolve_commit(target_rev)

    check_threshold_provenance(report, now)
    check_surface_sweep(report, target, declared)
    check_surface_extractable(report, target, declared)

    if surface_only:
        report.skip("pin ancestry (a) -- needs the consumer checkout")
        report.skip("pin distance in days and commits (b) -- needs the consumer checkout")
        report.skip("FFI surface drift since the pin (c) -- needs the consumer checkout")
        report.skip("pin agreement (d) -- needs the consumer checkout")
        report.skip("surface-crate coverage (e) -- needs the consumer checkout")
        return report

    if consumer_root is None:
        raise CannotEvaluate(
            "no consumer checkout given; the pin lives in the consumer repo, so the pin checks "
            "cannot be evaluated without it (CI must check the consumer repo out)"
        )
    if not consumer_root.is_dir():
        raise CannotEvaluate("the given consumer checkout path is not a directory")

    for consumer in manifest["consumers"]:
        name = str(consumer.get("name", "<unnamed>"))
        manifests = [str(m) for m in consumer.get("cargo_manifests", [])]
        if manifests:
            dependencies = consumer_dependency_names(consumer_root, manifests)
            check_surface_coverage(report, target, declared, name, dependencies)
        else:
            report.skip(f"surface-crate coverage for {name} -- no cargo_manifests declared")

        dated: list[tuple[str, str, int]] = []
        for pin in consumer["pins"]:
            pin_name = f"{name}/{pin.get('name', '<unnamed>')}"
            rev = read_pin(consumer_root, pin)
            pin_ts = check_pin_freshness(report, pin_name, rev, target, now)
            dated.append((pin_name, rev, pin_ts))
            if pin.get("governs_ffi_surface") is True:
                check_surface_drift(report, pin_name, rev, target, declared)
        check_pin_agreement(report, dated)

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fail when a consumer repo's pin on theyos has stopped telling the "
            "truth: a pin off the mainline, a pin too far behind in days or "
            "commits, disagreeing pins, a cross-repo FFI surface the consumer "
            "does not consume, or an FFI surface that moved since the pin. "
            "Output names repo-relative paths only; the consumer checkout path "
            "is never echoed."
        )
    )
    parser.add_argument(
        "--consumer-repo",
        help="path to a checkout of the consumer repo (required unless --surface-only)",
    )
    parser.add_argument(
        "--manifest",
        default=str(REPO_ROOT / DEFAULT_MANIFEST),
        help="path to the cross-repo boundary manifest",
    )
    parser.add_argument(
        "--target-rev",
        default=DEFAULT_TARGET_REV,
        help="rev the pins are measured against",
    )
    parser.add_argument(
        "--surface-only",
        action="store_true",
        help=(
            "run ONLY the checks that need no consumer checkout. This is a "
            "partial run: it reports what it did not check and cannot catch a "
            "stale pin. CI must run the full gate."
        ),
    )
    parser.add_argument(
        "--print-surface",
        action="store_true",
        help="print the extracted uniffi surface at the target rev and exit",
    )
    parser.add_argument(
        "--now",
        type=int,
        default=None,
        help="unix time to measure staleness from (testing; defaults to now)",
    )
    args = parser.parse_args(argv)

    now = args.now if args.now is not None else int(time.time())
    consumer_root = Path(args.consumer_repo) if args.consumer_repo else None

    try:
        if args.print_surface:
            manifest = load_manifest(Path(args.manifest))
            target = resolve_commit(args.target_rev)
            surface, missing = surface_at(target, [str(p) for p in manifest["surface_files"]])
            for path in missing:
                print(f"MISSING {path}")
            for path, items in sorted(surface.items()):
                print(f"# {path} ({len(items)} items)")
                for item in items:
                    print(item)
            return EXIT_OK

        report = run(
            manifest_path=Path(args.manifest),
            consumer_root=consumer_root,
            target_rev=args.target_rev,
            now=now,
            surface_only=args.surface_only,
        )
    except Malformed as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return EXIT_MALFORMED
    except CannotEvaluate as error:
        print(f"CANNOT EVALUATE: {error}", file=sys.stderr)
        return EXIT_CANNOT_EVALUATE

    for note in report.notes:
        print(f"note: {note}")
    for skipped in report.unchecked:
        print(f"NOT CHECKED: {skipped}")

    if report.errors:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return EXIT_VIOLATION

    if report.unchecked:
        print("OK (PARTIAL): theyos-side cross-repo surface checks passed; pin checks were not run")
    else:
        print("OK: cross-repo pins are ancestors, within bounds, in agreement, and the FFI surface has not moved")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
