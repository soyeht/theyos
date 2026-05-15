#!/usr/bin/env python3
"""Flip `tier: detected` → `tier: available` for claws that passed verify.

Inputs:
- claws/verify-results.json (verify_status: ok|failed|pending)
- claws/manifest.yml (source of truth)

Reads from the repo root (cwd). Idempotent: re-running is a no-op if all
passing claws are already promoted.
"""
import json
import pathlib
import re
import sys


def main() -> int:
    root = pathlib.Path.cwd()
    results_path = root / "claws" / "verify-results.json"
    manifest_path = root / "claws" / "manifest.yml"

    if not results_path.exists():
        print(f"error: {results_path} not found", file=sys.stderr)
        return 1
    if not manifest_path.exists():
        print(f"error: {manifest_path} not found", file=sys.stderr)
        return 1

    results = json.loads(results_path.read_text())
    passing = {name for name, r in results.items() if r.get("verify_status") == "ok"}
    failing = {name for name, r in results.items() if r.get("verify_status") == "failed"}
    print(f"verify-results: {len(passing)} ok, {len(failing)} failed")
    print(f"  passing: {sorted(passing)}")
    print(f"  failing: {sorted(failing)}")

    lines = manifest_path.read_text().splitlines()
    out = []
    current = None
    promoted = []
    entry_re = re.compile(r"^  ([a-z][a-z0-9-]*):$")

    for line in lines:
        m = entry_re.match(line)
        if m:
            current = m.group(1)
        if current in passing and line == "    tier: detected":
            out.append("    tier: available")
            promoted.append(current)
        else:
            out.append(line)

    if not promoted:
        print("no promotions needed (already up-to-date or no passes)")
        return 0

    manifest_path.write_text("\n".join(out) + "\n")
    print(f"promoted {len(promoted)}: {promoted}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
