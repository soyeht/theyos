# Agent operations index

**Read this first.** It is the map an agent needs before asking the owner
anything operational: where things live, what is already authorized, which
questions have already been answered, and how to measure this repo without
getting it wrong.

It exists because context runs out and sessions get cleared, and the same
question then gets asked a second and third time about something already decided
or already granted. That is the failure this file prevents.

This file is **tracked in git and the repository is public.** It therefore
contains **no addresses, no account identifiers, no credentials and no
endpoints** — only names, roles and pointers.

## 0. Why this file, and not `CLAUDE.md`

`CLAUDE.md` and `AGENTS.md` at the repo root are listed in `.gitignore` (they are
ignored on `origin/main`, not merely uncommitted here). Untracked files do not
exist in a linked worktree, a fresh clone or a CI checkout, so an agent starting
anywhere but the owner's primary checkout **never sees them**. Both carry a
pointer back here; this file is the copy that actually travels. Put durable
operational knowledge here, never only there.
`MEASURED 2026-08-06 origin/main@e60bad85`

## 1. The private operator store

Real values live **outside the repository**, at:

```
~/.soyeht-ops/          (mode 0700, on the owner's workstation)
├── README.md           why it exists and the rules for writing to it
├── authorizations.md   what agents may do without asking, dated, in the owner's words
├── infrastructure.md   hosts, the relay VPS, the tailnet — addresses, capacity, access
└── apple.md            Apple developer account state: granted, known, still unknown
```

**Rules, restated here because this file is the one every agent sees:**

1. Read `~/.soyeht-ops/` **before** escalating anything operational.
2. Write to it the **moment** something is granted or discovered — not later.
   A grant recorded only in a session transcript will be re-requested.
3. Never copy a value from it into this repo, a commit message, a PR, a log, a
   screenshot or an agent message. Refer to things by alias.
4. Mark unknowns as `UNKNOWN — ask once, then record`, so the next agent knows
   exactly which single question is still open.
5. Date every entry.

If `~/.soyeht-ops/` is missing on the machine you are running on, say so and ask
for it to be shared — do not reconstruct it from guesses.

## 2. Aliases used in all public text

| alias | means |
|---|---|
| `Relay-R` | the rented relay VPS |
| `Device-D` | an owner/member iPhone |
| `App-M` | the Soyeht macOS app and its engine |
| `Claw-M` / `Claw-L` | a macOS claw, a Linux claw |
| `Mesh-C` | the mesh control plane (discovery, authorization, offers, revocation) |
| `Member-M1`, `Member-M2`, … | distinct household members |

Never a real hostname, IP outside documentation ranges, device name, account
name, relay endpoint, local path, secret or key — in any file, PR or screenshot.

## 3. Where the code is, and the cross-repo hazard

| track | plan | one-line state |
|---|---|---|
| VPN to a claw | `docs/product-a-per-claw-vpn-plan.md` | datapath observed on a dev host; not activated |
| the same, from an iPhone | `docs/product-a-mobile-claw-control-vpn-plan.md` | Rust FFI shaped for `NEPacketTunnel`; no iOS client yet |
| VPN device ↔ device | `docs/product-a-device-mesh-vpn-plan.md` | large codebase, most of it outside the build graph |
| free / paid boundary | `docs/soyeht-tiers-and-entitlement-plan.md` | seam designed, pricing undecided |
| relay capacity and cost | `docs/soyeht-relay-vps-capacity-and-cost-plan.md` | one small VPS serves Share today |
| Share (shipped) | `docs/share-foundation-boundary-map.md` | in `main` |

Cross-repo protocol contract: `docs/household-protocol.md`.

**The macOS and iOS applications are not in this repository.** Zero `.swift` and
zero `.xcodeproj` files are tracked here `MEASURED 2026-08-06 origin/main@e60bad85`.
They live in **`github.com/soyeht/soyeht-ios`**.

**Live hazard — three pins, and the one that matters is not in `Cargo.toml`.**
The iOS repo takes `household-rs` as a **path** dependency on an ignored vendored
checkout; the immutable rev lives in a shell variable in its FFI build script,
and two further pins govern **data**, not the compiled surface — so
`.github/workflows/contracts-cross-repo-sync.yml` can be green while saying
nothing about the FFI. The authoritative list of pins and which one governs the
surface is `admin/contracts/cross-repo/v1/ios_ffi_boundary_v1.json`; the gate
below reads it. Measured 2026-08-06 against `origin/main@e60bad85`: the surface
pin is 6 days behind and carries the VPN FFI; the two data pins are 20–22 days
behind and disagree with it.

**Method warning, and the reason this paragraph is short.** An earlier revision
here said that pin was 858 commits and six weeks behind. The number came from a
clone sitting on a **local `main` 17 commits behind `origin/main`**, reading a
dependency form the consumer had already stopped using — and a gate was designed
around it. Before quoting any cross-repo pin: confirm the clone's HEAD against
`origin/main`, and confirm *which file* the consumer reads it from today. Paths
in the other repository do not belong here; the manifest holds them.

## 4. Gates that keep this from happening again

Each is a `scripts/check-*.py` with a co-located `scripts/test_*.py`, run with
`uv run`. A row carrying a pending marker has not landed yet, and this index goes
**red** on that marker's date. From a checkout that is behind `main`, add
`--also-in origin/main` so mapped paths resolve against the tree this lands on.

| gate | goes red when |
|---|---|
| `check-agent-operations-index.py` | this index is untracked, over-long, has a dead link, leaks a value, or carries a claim that has aged out |
| `check-cross-repo-pin-freshness.py` | a consumer's pin is off-ancestry, too far behind in days or commits, predates an FFI surface change, or disagrees with the consumer's other pins |
| `check-plan-doc-freshness.py` | a plan's measured anchor is older than the code it claims to describe |
| `check-branch-hygiene.py` | a branch is behind `main` on files it touches, so merging it would delete shipped code |

## 5. Measuring this repo without getting it wrong

Four mistakes have each cost real time here.

- **Measuring the working tree and calling it `main`.** Local checkouts sit on
  old branches and linked worktrees sit on detached heads. Use
  `git show origin/main:<path>` and `git grep <pattern> origin/main -- <paths>`,
  and state which tree every number came from.
- **Counting code nothing builds.** `admin/rust/Cargo.toml` carries an `exclude`
  list — `mesh-session-control-model-rs` and `mesh-session-core-rs` are not
  workspace members. Check `exclude`, check each crate's `[features] default`,
  and check whether the engine references the module, *before* quoting a
  readiness number.
- **Confusing "CI compiles it" with "CI runs it".** Both excluded crates'
  *libraries* do compile in CI — `keystore-rs`'s `mesh-session` feature and
  `mesh-session-runtime-rs`'s `mesh-session-runtime` feature path-depend on
  `mesh-session-core-rs`, and the backend-ci feature-surface loop compiles every
  non-default feature. Their *tests* never execute: `cargo test --workspace`
  only reaches members. `mesh-session-control-model-rs` has no dependent at all,
  so nothing in CI compiles it.
  `MEASURED 2026-08-06 origin/main@e60bad85`
- **Assuming a feature-gated test ran.**
  `admin/rust/mesh-session-control-model-rs/tests/model_invariants.rs` declares
  `required-features = ["test-support", "roster-sync-unratified"]` — **two
  features at once**. The CI loop passes exactly one feature per invocation
  (`cargo check -p "${pkg}" --features "${feat}"`), so that target is never even
  compiled there, let alone run. A test target can be named in CI's universe and
  still be unreachable by CI's invocation shape.
  `MEASURED 2026-08-06 origin/main@e60bad85`

## 6. The dating rule — the one rule behind all four failures

**Every pin, threshold, readiness number and "measured" claim carries the date
and the tree it was taken from, and something must be able to go red when it
ages.** A number without an expiry is a number nobody re-evaluates; it stays
green while it rots.

Write it inline, exactly in the shape of these two examples, or the gate rejects
it — an ISO date, then the tree and the commit the claim was read from:

```
MEASURED 2026-08-06 origin/main@e60bad85
PENDING 2026-08-14
```

Write each marker as a code span. The tree must be one of `origin/main`, `main`,
`HEAD`, `worktree` or `soyeht-ios`, and a local one must resolve to a commit
here. A pending marker is a promise that expires on its date, and exempts its
line from the dead-link check until then.

`scripts/check-agent-operations-index.py` fails when a measured claim is older
than 30 days, when a pending date has passed, when a marker is malformed, and
when the file carries no measured claim at all. **The fix for a red is to
re-measure and restate the date — never to bump the date.**

Today's four instances, all the same failure:

1. An iOS pin six weeks stale, covering a crate that did not exist at the pin.
2. A 200-line status header a month old, seven of its assertions measurably false.
3. A branch named after shipped work whose merge would have deleted 1,594 lines.
4. Operational grants recorded only in transcripts, re-asked after every reset.

None of them was red. That is the whole problem: each was a number nobody
re-evaluated, and nothing existed that could age.

## 7. Test profile for Product A

Product A live tests, owner recovery, community relay, PTY/ClawSite and revoke
smokes use the **dev** macOS app, the **dev** state profile and the **dev**
engine endpoint. Never the production app, production state, the production
engine port or the legacy production household — unless the owner explicitly
asks for production validation.

Exact bundle identifiers, ports and profile names: `~/.soyeht-ops/apple.md` and
`~/.soyeht-ops/infrastructure.md`.

## 8. Where authorization actually lives

`~/.soyeht-ops/authorizations.md` is the record. Do not infer a grant from a
neighbouring one: authorization for a role, a host or a phase does not extend to
the next.

Still requiring an explicit, current owner decision regardless of anything else:
**production activation, production deploy, flag flips affecting real
households, and publishing private evidence outside the private store.**
