#!/usr/bin/env python3
"""Structural gate over `cargo metadata` output.

Answers three questions that prose cannot, and that reading Cargo.toml cannot
either, because both describe intent while the resolve graph describes what
cargo actually built:

  cycles   - is the package graph acyclic, and over WHICH edge kinds?
  closure  - what is the full transitive closure of a package?
  contain  - is that closure inside an allowlist and disjoint from a denylist?

Deliberate choices, each of which changes what the gate can claim:

* Cycle detection runs here rather than resting on `cargo metadata` exiting 0.
  Cargo REFUSES to resolve a cycle among normal/build edges (it fails with
  "cyclic package dependency"), so RC=0 already proves that much. It does NOT
  prove the graph is acyclic: cargo deliberately TOLERATES dev-dependency
  cycles (A dev-depends on B, B depends on A). Such a cycle still means the
  crate cannot later be extracted or published independently, so a gate that
  reports "acyclic" on cargo's exit code alone is answering a narrower question
  than the one being asked. This tool reports the two edge sets separately.

* Containment is expressed as an ALLOWLIST, with the denylist only as a
  cross-check. A denylist fails open for every package nobody thought to name;
  an allowlist fails closed. The denylist is kept anyway because when it fires
  it names the offender, which is the more useful failure message.

* Metadata is read WITHOUT `--filter-platform`, so the closure is the union
  over every target platform. That is a superset of any single build, which is
  the conservative direction for an "X must not reach Y" claim.

* PRESENCE, not reachability, is what the feature-off phase forbids. A crate can
  sit in the resolve graph with no normal edge to it -- reached only through
  [dev-dependencies] -- and that still counts: a dev-only edge compiles the crate
  for test builds and leaves it one feature flag from a normal one. The phase
  tests presence and its message must say presence. It said "reachable" once, and
  a reader went and measured reachability with `cargo tree`, got a correct answer
  to a different question, and wrote a mitigation into the ledger. The word did
  that, not the missing detail.

* LIMIT, declared 2026-08-05 (@khai, measured in both feature arms): a crate
  compiled in by `#[path = "..."]` produces NO NODE and NO EDGE. `keystore-rs`
  compiles `mesh-session-control-model-rs`'s real sources under its
  `mesh-session` feature, and that crate is absent from the resolve graph with
  the feature both OFF and ON. So the opening claim -- that the resolve graph
  describes what cargo actually built -- holds for dependency edges and NOT for
  source inclusion. No graph-based check can see a `#[path]` crate; a containment
  claim across such a boundary needs a different instrument.
"""

from __future__ import annotations

import argparse
import json
import sys


def load(path: str) -> dict:
    if path == "-":
        return json.load(sys.stdin)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def name_map(md: dict) -> dict[str, str]:
    """id -> package name, taken from `packages[]` rather than parsed out of
    the id.

    Parsing looks like it works and does not. A registry id ends in
    `#serde@1.0.0`, but a PATH package whose directory already carries the
    name ends in just `#0.1.0`, so splitting on `#`/`@` yields "0.1.0" as the
    package name. Every workspace-local crate — precisely the ones this gate
    exists to reason about — takes that branch, so an allow/deny list would
    have been compared against version strings and matched nothing. A gate
    that can only ever pass is worse than no gate.
    """
    return {p["id"]: p["name"] for p in md.get("packages", [])}


def build_graph(md: dict) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Return (edges_nondev, edges_all) keyed by package id.

    `dep_kinds[].kind` is null for a normal dependency, "dev" or "build"
    otherwise. A dep entry can carry several kinds at once (same package used
    normally and in dev), so an edge counts as non-dev if ANY of its kinds is.
    """
    nondev: dict[str, list[str]] = {}
    every: dict[str, list[str]] = {}
    for node in md.get("resolve", {}).get("nodes", []):
        nid = node["id"]
        nondev.setdefault(nid, [])
        every.setdefault(nid, [])
        for dep in node.get("deps", []):
            did = dep["pkg"]
            every[nid].append(did)
            kinds = [k.get("kind") for k in dep.get("dep_kinds", [])] or [None]
            if any(k is None or k == "build" for k in kinds):
                nondev[nid].append(did)
    return nondev, every


def find_cycles(edges: dict[str, list[str]], nm: dict[str, str] | None = None) -> list[list[str]]:
    """Iterative DFS with an explicit stack; returns every back-edge cycle.

    `nm` maps id -> display name. It is threaded in rather than resolved by a
    module-level helper because the naming path is only exercised when a cycle
    IS found: a mistake there stays invisible through every green run and
    surfaces as a crash at the exact moment the gate is supposed to report a
    failure.
    """
    label = (lambda i: nm.get(i, i)) if nm else (lambda i: i)
    WHITE, GREY, BLACK = 0, 1, 2
    colour: dict[str, int] = {n: WHITE for n in edges}
    cycles: list[list[str]] = []

    for root in edges:
        if colour[root] != WHITE:
            continue
        stack: list[tuple[str, int]] = [(root, 0)]
        path: list[str] = [root]
        colour[root] = GREY
        while stack:
            node, idx = stack[-1]
            kids = edges.get(node, [])
            if idx < len(kids):
                stack[-1] = (node, idx + 1)
                kid = kids[idx]
                if kid not in colour:
                    colour[kid] = WHITE
                    edges.setdefault(kid, [])
                if colour[kid] == GREY:
                    cut = path.index(kid) if kid in path else 0
                    cycles.append([label(p) for p in path[cut:]] + [label(kid)])
                elif colour[kid] == WHITE:
                    colour[kid] = GREY
                    stack.append((kid, 0))
                    path.append(kid)
            else:
                colour[node] = BLACK
                stack.pop()
                path.pop()
    return cycles


def resolve_root(md: dict, name: str) -> str | None:
    for pkg in md.get("packages", []):
        if pkg["name"] == name:
            return pkg["id"]
    return None


def closure(edges: dict[str, list[str]], root: str) -> set[str]:
    seen: set[str] = set()
    stack = [root]
    while stack:
        cur = stack.pop()
        for nxt in edges.get(cur, []):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def cmd_cycles(args: argparse.Namespace) -> int:
    md = load(args.metadata)
    nondev, every = build_graph(md)
    nm = name_map(md)
    c_nondev = find_cycles({k: list(v) for k, v in nondev.items()}, nm)
    c_all = find_cycles({k: list(v) for k, v in every.items()}, nm)

    print(f"packages_in_resolve={len(every)}")
    print(f"cycles_nondev={len(c_nondev)}")
    for cyc in c_nondev:
        print("  CYCLE(normal|build): " + " -> ".join(cyc))
    print(f"cycles_including_dev={len(c_all)}")
    for cyc in c_all:
        print("  CYCLE(with dev): " + " -> ".join(cyc))

    if c_nondev:
        print("VERDICT=FAIL reason=cycle_in_normal_or_build_edges")
        return 2
    if c_all:
        # Cargo tolerates these; this gate does not silently inherit that.
        print("VERDICT=FAIL reason=cycle_only_via_dev_edges")
        return 3
    print("VERDICT=PASS scope=acyclic_over_normal_build_and_dev_edges")
    return 0


def cmd_contain(args: argparse.Namespace) -> int:
    md = load(args.metadata)
    root_id = resolve_root(md, args.root)
    if root_id is None:
        print(f"VERDICT=SKIP reason=root_package_absent root={args.root}")
        return 10  # distinct RC: a skip must never be readable as a pass
    nm = name_map(md)
    _, every = build_graph(md)
    reached_ids = closure(every, root_id)
    if args.local_only:
        # Registry crates are hundreds of names that churn on every bump; the
        # boundary this gate defends is between OUR crates, so the allowlist is
        # stated over workspace-local packages and the scope is declared here
        # rather than left implicit in a hand-maintained list.
        local = workspace_local(md)
        reached_ids = {i for i in reached_ids if i in local}
    reached = {nm[i] for i in reached_ids}
    reached.discard(args.root)

    allow = set()
    if args.allow:
        with open(args.allow, encoding="utf-8") as fh:
            allow = {
                ln.strip()
                for ln in fh
                if ln.strip() and not ln.lstrip().startswith("#")
            }
    deny = set(args.deny or [])

    outside = sorted(reached - allow) if args.allow else []
    hits = sorted(reached & deny)

    print(f"root={args.root}")
    print(f"closure_size={len(reached)}")
    for name in sorted(reached):
        print(f"  dep {name}")
    if args.allow:
        print(f"outside_allowlist={len(outside)}")
        for name in outside:
            print(f"  OUTSIDE {name}")
    print(f"denylist_hits={len(hits)}")
    for name in hits:
        print(f"  FORBIDDEN {name}")

    if hits:
        print("VERDICT=FAIL reason=denylist_reached")
        return 2
    if outside:
        print("VERDICT=FAIL reason=outside_allowlist")
        return 3
    print("VERDICT=PASS")
    return 0


WATCHLIST = ["snow", "mesh-session-core-rs", "mesh-session-control-model-rs"]


def workspace_local(md: dict) -> set[str]:
    return {p["id"] for p in md.get("packages", []) if p["id"].startswith("path+")}


def summarise(md: dict) -> dict:
    """Compact, diffable summary of the graph.

    Committing a whole `cargo metadata` dump as a baseline would be ~670
    packages of registry noise that churns on every unrelated bump, so the
    baseline would rot into "always different" and stop being read. This keeps
    only what the criterion is about: which workspace-local packages exist,
    the edges between them, and — for each watched package — the exact set of
    parents that pull it in.
    """
    nm = name_map(md)
    local = workspace_local(md)
    _, every = build_graph(md)
    edges: dict[str, list[str]] = {}
    parents: dict[str, list[str]] = {w: [] for w in WATCHLIST}
    for node_id, kids in every.items():
        if node_id in local:
            edges[nm[node_id]] = sorted({nm[k] for k in kids if k in local})
        for kid in kids:
            if nm[kid] in parents:
                parents[nm[kid]].append(nm[node_id])
    return {
        "workspace_local_packages": sorted(nm[i] for i in local),
        "workspace_local_edges": dict(sorted(edges.items())),
        "watchlist_parents": {k: sorted(set(v)) for k, v in sorted(parents.items())},
    }


def cmd_baseline(args: argparse.Namespace) -> int:
    print(json.dumps(summarise(load(args.metadata)), indent=2, sort_keys=True))
    return 0


def cmd_regress(args: argparse.Namespace) -> int:
    """`no NEW edge` criterion.

    Stated this way because the absolute form is already false at the base:
    `snow` sits in the default graph via household-rs and server-rs, so
    "default has no snow" can never pass and would have to be waived, which is
    how a gate becomes decoration. What a change CAN be held to is introducing
    no new parent for a watched package.
    """
    base = json.load(open(args.baseline, encoding="utf-8"))
    cand = summarise(load(args.metadata))

    new_pkgs = sorted(
        set(cand["workspace_local_packages"]) - set(base["workspace_local_packages"])
    )
    print(f"new_workspace_local_packages={len(new_pkgs)}")
    for name in new_pkgs:
        print(f"  NEW-PKG {name}")

    # An exemption is scoped to ONE (watched, parent) pair, spelled WATCHED=PARENT.
    # It used to be a bare parent name applying to every watched package at once,
    # which is wider than any caller ever meant: `--allow-new-parent household-rs`,
    # written to permit household-rs -> mesh-session-core-rs, silently also permits
    # household-rs -> mesh-session-control-model-rs, and PHASE 2 constrains the
    # parent set of core-rs only -- so that second edge would have appeared with
    # both phases green. A bare name is now a hard error rather than a quietly
    # coarser reading; the sole bare use at the call site was measured inert
    # (identical output with and without it) before the form was changed.
    allowed = set()
    for spec in args.allow_new_parent or []:
        if "=" not in spec:
            print(f"ERROR --allow-new-parent must be WATCHED=PARENT, got {spec!r}")
            return 2
        w, _, p = spec.partition("=")
        if w not in WATCHLIST:
            print(f"ERROR --allow-new-parent names {w!r}, which is not watched: {WATCHLIST}")
            return 2
        allowed.add((w, p))

    violations = []
    for watched in sorted(set(base["watchlist_parents"]) | set(cand["watchlist_parents"])):
        b = set(base["watchlist_parents"].get(watched, []))
        c = set(cand["watchlist_parents"].get(watched, []))
        added = sorted(c - b)
        unexpected = [a for a in added if (watched, a) not in allowed]
        print(f"watch {watched}: base_parents={sorted(b)} added={added}")
        if unexpected:
            violations.append((watched, unexpected))

    for watched, adds in violations:
        for a in adds:
            print(f"  VIOLATION new parent for {watched}: {a}")
    if violations:
        print("VERDICT=FAIL reason=new_watchlist_edge")
        return 2
    print("VERDICT=PASS scope=no_new_parent_for_watched_packages")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_c = sub.add_parser("cycles", help="detect cycles, reporting edge kinds separately")
    p_c.add_argument("--metadata", required=True, help="cargo metadata JSON, or - for stdin")
    p_c.set_defaults(func=cmd_cycles)

    p_k = sub.add_parser("contain", help="closure of a package vs allow/deny lists")
    p_k.add_argument("--metadata", required=True)
    p_k.add_argument("--root", required=True)
    p_k.add_argument("--allow", help="file of allowed package names, one per line")
    p_k.add_argument("--deny", nargs="*", help="package names that must not be reachable")
    p_k.add_argument("--local-only", action="store_true", help="restrict the closure to workspace-local (path) packages")
    p_k.set_defaults(func=cmd_contain)

    p_b = sub.add_parser("baseline", help="emit a compact, diffable graph summary")
    p_b.add_argument("--metadata", required=True)
    p_b.set_defaults(func=cmd_baseline)

    p_r = sub.add_parser("regress", help="no NEW parent for a watched package")
    p_r.add_argument("--metadata", required=True)
    p_r.add_argument("--baseline", required=True)
    p_r.add_argument("--allow-new-parent", nargs="*", metavar="WATCHED=PARENT",
                     help="exempt ONE watched package gaining ONE named parent, e.g. "
                          "mesh-session-core-rs=household-rs. A bare parent name is "
                          "rejected: it would exempt that parent for every watched package.")
    p_r.set_defaults(func=cmd_regress)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
