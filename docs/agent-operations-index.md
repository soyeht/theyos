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

**There is no plan document here, and that is deliberate.** The whole planning
corpus — 37 plan, design, follow-up and execution-artifact documents — was
deleted on 2026-08-06 because the product is being replanned. A superseded plan
an agent still reads is worse than none: it reads as current, it is specific, and
it sends work somewhere the owner already abandoned. **Finding no plan is the
answer, not a broken checkout** — ask the owner rather than inferring one from
code, a branch name or git history. They survive at `origin/main@74f5c0e7`;
read them, never resume them. `MEASURED 2026-08-06 origin/main@74f5c0e7`

The absence has a deadline: `check-plan-doc-freshness.py` passes with nothing
enrolled only until `PLAN_ENROLLMENT_DEADLINE`, then fails. Enrol the new plan as
`anchored` in `docs/doc-freshness-enrollment.json`, name it in
`REQUIRED_ANCHORED`, replace this section — and do not move the date. Still live,
and not plans: `share-foundation-boundary-map.md`, `household-protocol.md` (cited
by nine Rust sources), and the contracts under `owner-mesh-rendezvous/`,
`owner-site-a2-dataplane/` and `contracts/`. They survive only because live code
cites them; that is the test, not seniority. **When the new plan ships, sweep
again and delete whatever it did not use** — standing owner instruction, recorded
in `~/.soyeht-ops/authorizations.md`.

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
  and state which tree every number came from. This is how the cross-repo pin
  above was once reported as 858 commits behind: a clone on a local `main` 17
  commits stale, reading a dependency form the consumer had already abandoned —
  and a gate was designed around the wrong number.
- **Counting code nothing builds.** `admin/rust/Cargo.toml` carries an `exclude`
  list — `mesh-session-control-model-rs` and `mesh-session-core-rs` are not
  workspace members. Check `exclude`, check each crate's `[features] default`,
  and check whether the engine references the module, *before* quoting a
  readiness number.
- **Confusing "CI compiles it" with "CI runs it".** The excluded crates'
  *libraries* compile in CI via feature path-deps and the feature-surface loop;
  their *tests* never execute, because `cargo test --workspace` reaches only
  members. The same gap hid a red end-to-end test behind `dev_t1_datapath` for
  weeks — clippy compiled it every push, nothing ran it, until backend-ci gained
  a step that does. **Ask which invocation reaches a target, not whether the
  target exists.** A target can be named in CI's universe and still be
  unreachable by CI's invocation shape: `model_invariants.rs` needs *two*
  features at once and the loop passes exactly one.
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

Instances, none red at the time: a stale iOS pin; a month-old header with seven
false assertions; a branch whose merge would have deleted 1,594 lines; grants
recorded only in transcripts. The sharpest: an end-to-end test built on a
hardcoded future timestamp while the code re-read the real clock, so it could
only pass in a ten-minute window in 2027 — CI compiled it every push and ran it
never. **Compiling a test proves it type-checks; running it proves what it
asserts.**

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
