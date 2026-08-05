# Lane C — measured evidence

Base `cf3969fd`, `rustc 1.92.0 (ded5c06cf 2025-12-08)`, `cargo 1.92.0`.
At this commit `mesh-session-runtime-rs` **does not exist** — no directory, and
`git grep "mesh-session-runtime\|mesh_session_runtime"` returns nothing. Every
claim below about the proposed crate was therefore obtained by grafting a
skeleton manifest into a throwaway tree (`git archive cf3969fd | tar -x -C
$(mktemp -d)`), never by editing this branch.

## Structural gate at base

    cd admin/rust && bash scripts/graph-gate/run_gate.sh structural
    => pass=4 fail=0 skip=3, exit 0

The three SKIPs are the runtime-crate configurations, reported with their own
marker. They are **not** counted as passes: a gate that reports green for a
configuration it never ran is the failure this lane exists to prevent.

## The refutation: unconditional member deps defeat feature-OFF

Probe A — the crate as first specified (`keystore-rs = { workspace = true,
features = ["mesh-session"] }`, not optional), added to `members`:

| instrument | command | result |
|---|---|---|
| resolve graph | `cargo metadata --format-version 1 --offline` (no `--features`) | `keystore-rs features=['mesh-session']`, `mesh-session-core-rs` **present** |
| feature edge | `cargo tree --offline --workspace -e features -i keystore-rs` | `keystore-rs feature "mesh-session"` ← `mesh-session-runtime-rs` |
| real build | `cargo check --offline -p keystore-rs -p mesh-session-runtime-rs` | emits `libmesh_session_core_rs-*.rmeta` |
| **negative control** | `cargo check --offline -p keystore-rs` alone | emits **zero** `mesh_session_core` artifacts |

At the base the same default query gives `keystore-rs features=[]` and no
`mesh-session-core-rs`. So the member turns the D4 surface on for every
workspace-wide build, silently.

The control is what makes this a measurement rather than a story: without it,
"core got compiled" would be equally consistent with core always being
compiled.

## The fix, also measured

Probe B — the member's deps made `optional` behind its own non-default
`mesh-session-runtime` feature:

    workspace default: keystore-rs=[]                     core present = False
    feature ON:        keystore-rs=['mesh-session']       core present = True
    cycles, both states: 0 over normal|build AND dev edges

## Gate teeth (the gate is an instrument, so it gets tested too)

    regress vs baseline-cf3969fd.json, probe A -> RC=2  VERDICT=FAIL
        VIOLATION new parent for mesh-session-core-rs: keystore-rs
        VIOLATION new parent for snow: mesh-session-core-rs
    regress vs baseline-cf3969fd.json, probe B -> RC=0  VERDICT=PASS

Red on the rejected design, green on the adopted one. A gate only observed
passing has not been shown able to fail.

Cycle detection likewise: on synthetic input it returns `[]` for
`a→b→c`, `['alpha','beta','gamma','alpha']` for `a→b→c→a`, and
`['alpha','beta','alpha']` for a 2-cycle.

## Two corrections to the brief, both measured

1. **"default without mesh/snow" is false at the base.** `household-rs` and
   `server-rs` depend on `snow` unconditionally, so `snow` is already in the
   default graph independently of this work. Criterion reformulated as *no NEW
   parent for a watched package*, which is what `regress` implements.
2. **`tunnel-wire-rs` is not a Product A/nvpn crate.** It appears in the new
   crate's closure via `household-rs`, and the name invites the wrong
   conclusion. Its own manifest and crate docs say it is the S0 *neutral* wire
   mechanics, extracted specifically so that `household-rs` is **absent** from
   its dependencies and claw authority cannot be reached from it. Read, not
   inferred.

## Declared limits

- **Package granularity.** The closure says `server-rs` — where the Share relay
  binary lives — is unreachable. It cannot say "no Share code is reachable",
  because `household-rs` contains `claw_share_data_tunnel.rs` and the closure
  does not resolve modules within a crate. Do not round this up.
- Phase 3/4 (compiled matrix, `--all-targets`) is defined in `run_gate.sh` but
  the runtime-crate rows can only run once the crate exists.
- `cargo metadata` is read without `--filter-platform`, so closures are the
  union across targets — a superset, which is the conservative direction.
