#!/usr/bin/env python3
"""Demote failed-verify claws to tier: catalog with skip_install_reason.

For each failed claw (curated list below), this script:
  - flips `tier: detected` → `tier: catalog`
  - inserts `skip_install_reason: "..."` immediately after tier
  - strips `install_template:`, `install_plan_source:`, and the full `install:`
    YAML block (build.rs invariant: catalog claws are metadata-only)

Idempotent.
"""
import pathlib
import re
import sys

DEMOTE = {
    "microclaw": "cargo install fails (exit 101) with stderr suppressed in plan; needs re-investigation with verbose output before re-verify.",
    "dr-claw": "npm install fails because node-gyp build of node-pty requires python3-distutils; install plan needs python3-setuptools in system_deps.",
    "kkclaw": "detector guessed npm package name `openclaw-kkclaw` but it is not published to npmjs.org (404). Needs manual investigation to find real install path.",
    "clawarm": "detector guessed pip package name `clawarm-bridge` but it is not published to PyPI. Needs manual investigation to find real install path.",
    "rivonclaw": "pnpm install + pnpm build timed out at 900s. Likely needs min_ram_mb bump or extended SSH timeout.",
    "clawwork": "install plan has apt/pip/npm dependency conflict during manual-shell execution. Needs install plan rewrite.",
    "openclawbox": "upstream installer (scripts/install.sh) requires Docker or Node>=20 but install plan only installs curl/git/bash. Needs node>=20 in system_deps.",
}

ENTRY_RE = re.compile(r"^  ([a-z][a-z0-9-]*):$")
STRIP_FIELD_RE = re.compile(r"^    (install_template|install_plan_source):")
INSTALL_BLOCK_RE = re.compile(r"^    install:\s*$")


def process_entry(block_lines: list[str], name: str) -> list[str]:
    """Rewrite a single claw's lines to demote it to catalog."""
    reason = DEMOTE[name]
    out: list[str] = []
    skip_child_indent: str | None = None

    for line in block_lines:
        # Skip children of a stripped `install:` block.
        if skip_child_indent is not None:
            if line.startswith(skip_child_indent) and line.strip():
                continue
            skip_child_indent = None

        if line == "    tier: detected":
            out.append("    tier: catalog")
            out.append(f'    skip_install_reason: "{reason}"')
            continue

        if line.lstrip().startswith("skip_install_reason:"):
            continue  # dedupe on re-run

        if STRIP_FIELD_RE.match(line):
            continue

        if INSTALL_BLOCK_RE.match(line):
            skip_child_indent = "      "  # 6 spaces
            continue

        out.append(line)

    return out


def main() -> int:
    manifest_path = pathlib.Path.cwd() / "claws" / "manifest.yml"
    if not manifest_path.exists():
        print(f"error: {manifest_path} not found", file=sys.stderr)
        return 1

    lines = manifest_path.read_text().splitlines()

    # Split into entry blocks. Header lines (before the first entry) get
    # treated as an "entry" with name=None and are passed through as-is.
    blocks: list[tuple[str | None, list[str]]] = []
    current_name: str | None = None
    current_lines: list[str] = []
    for line in lines:
        m = ENTRY_RE.match(line)
        if m:
            if current_lines or current_name is not None:
                blocks.append((current_name, current_lines))
            current_name = m.group(1)
            current_lines = [line]
        else:
            current_lines.append(line)
    blocks.append((current_name, current_lines))

    # Rewrite blocks for demoted claws.
    out_blocks: list[list[str]] = []
    demoted: list[str] = []
    for name, block_lines in blocks:
        if name in DEMOTE:
            out_blocks.append(process_entry(block_lines, name))
            demoted.append(name)
        else:
            out_blocks.append(block_lines)

    new_lines = [line for block in out_blocks for line in block]
    manifest_path.write_text("\n".join(new_lines) + "\n")

    if not demoted:
        print("no demotions applied")
    else:
        print(f"demoted {len(demoted)}: {demoted}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
