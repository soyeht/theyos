# Branch inventory — the VPN / Product A tracks

**Measured against `origin/main` = `e60bad85` (2026-08-06, "Merge pull request #422: mesh-session
lifecycle, D1 runtime facade, nonce-ledger bridge, Lane C graph gate").**
**Triage date: 2026-08-06.**

<!-- doc-freshness-anchor
measured: 2026-08-06
sha: e60bad85313eb39c9a000a29852bde1a944e425e
paths:
  - admin/rust/server-rs/src/claw_vpn_*
  - admin/rust/server-rs/src/mobile_claw_vpn_*.rs
  - admin/rust/household-rs/src/claw_vpn*.rs
  - admin/rust/claw-share-bridge-rs/
  - admin/rust/t1-iptunnel-dev-runner-rs/
  - admin/rust/mesh-session-core-rs/
  - admin/rust/tunnel-wire-rs/
-->

## Why this file exists

Over roughly two months of VPN work, agents opened branches, measured things on them, and moved
on. Nothing recorded what those branches held or what had already been decided about them. The
result is a loop: a branch is rediscovered, re-analysed from scratch, judged "probably has
something", and re-abandoned. The analysis cost is paid again every few weeks and the conclusion
is lost again every time.

This document is the durable answer to *"what is all this and what do we throw away"*. It is not
a cleanup script. It is the record that makes the cleanup safe and makes the re-analysis
unnecessary.

**If you are an agent about to investigate a branch: read the verdict table first.** If the branch
is in it, the work is done — act on the verdict or challenge it with new evidence, but do not
re-derive it. If your conclusion differs, say which command produced the difference and update
this file with a new dated row rather than replacing the old one.

**A branch inventory with no date is worse than none**, because it will be believed after it has
stopped being true. Every claim below is anchored to the tree named in the header. Re-measure
before trusting it against a different `main` — §6 has the commands.

## 1. Method

Three rules produced these verdicts, and re-running the triage without them will produce wrong
answers:

1. **Classify by patch-id, not by SHA.** `git cherry origin/main <branch>` marks each commit `+`
   (not upstream) or `-` (already upstream under a different SHA). Rebases, cherry-picks and
   squash-merges all change the SHA while preserving the patch. Comparing SHAs, or comparing two
   patch files, answers a different question than "is this work on main".
2. **"Ahead" is not "valuable".** A long-lived branch is almost always ahead because `main` moved
   underneath it, not because it holds something. The question is never *does it have unique
   commits* — it is *does its content still apply to today's main, and does main already have the
   capability by another route*. Several branches here were superseded by a **different mechanism**
   with a different name, which a symbol grep alone would miss (see §5).
3. **Never cite a line number across two trees.** Coordinates measured on a branch do not resolve
   on `main`. Cite the file and the symbol. Several branch-local docs violate this and will send
   readers to the wrong place with full confidence; that is called out per branch below.

Each branch was investigated independently against the tree in the header. Verdicts are one of:

| Verdict | Meaning |
|---|---|
| **LAND** | Content should go to `main` substantially as-is. |
| **SALVAGE** | Named parts are worth rescuing; the branch as a whole is not landable and should not be reopened as a PR. |
| **DROP** | Nothing to rescue. Delete the ref. |

No branch was deleted, pushed, force-pushed or modified to produce this document.

## 2. The arithmetic

At census time the repository carried **154 remote branches**. Of those:

| Class | Count | How established |
|---|---:|---|
| Merged into `origin/main` by graph | 79 | reachable from `main`; `git branch -r --merged` finds these |
| Squash-merged via a PR marked MERGED | 46 | **`git branch --merged` does NOT find these** |
| Zero unique commits by patch-id | 4 | `git cherry origin/main <branch>` emits no `+` line |
| **Provably disposable subtotal** | **129** | |
| Branch of an OPEN PR (out of scope here) | 11 | `gh pr list --state open` |
| Investigated individually | 12 remote + 1 local ref | this document |
| `main` itself | 1 | |

### The squash-merge trap — read this before triaging anything

**`git branch --merged` misses 46 branches whose work is fully on `main`.**

When a PR is squash-merged, GitHub creates one new commit on `main` with a new SHA and a new tree
lineage. The branch's own commits are never made reachable from `main`. `git branch --merged`
answers *"is this tip an ancestor of main"*, and for a squash-merge the answer is no — forever,
no matter how completely the work landed.

So anyone who triages with `git branch --merged` alone sees 79 merged branches and **75 apparently
unmerged ones**, concludes there is a mountain of live work, and starts investigating branches
whose content has been on `main` for months. That is a large share of how the last two months of
churn happened. The correct instrument is patch-id (`git cherry`) plus a PR-state lookup
(`gh pr list --state all --head <branch>`), used together — §6.

### Reconciliation against today's remote (re-measured 2026-08-06)

`git ls-remote --heads origin | wc -l` → **24**, and `gh api repos/<owner>/<repo>/branches` agrees.
Those 24 are exactly:

- `main` (1)
- the 11 open-PR heads (`#72, #85, #87, #339, #340, #357, #382, #383, #389, #418, #421`)
- the 12 remote branches investigated below

The 129 disposable branches are no longer present on the remote. **The count in the table above is
the census as taken; the remote today holds only the 25 branches that census left standing.**
Do not read "154" as a current number — read it as "this is how many were examined".

One extra ref is investigated here that is **not** on the remote:
`refs/remotes/review/pr340-preview`, a stale local-only mirror. See its row.

## 3. Verdict table

Unique-commit counts are `+` lines from `git cherry origin/main <branch>`, re-measured against
`e60bad85` on 2026-08-06.

| Branch | Uniq | Last activity | What it holds | Verdict | Conf. | Why, in one line |
|---|---:|---|---|---|---|---|
| `product-a-membership` | 284 | 2026-06-24 (`1101421d`) | The whole Product A "5G + mesh" working tree: claw-share ceremony, the nvpn mesh plane, the relay_stream Noise stack, community-relay productization, the Fase E audience model | **SALVAGE** | high | The keeper half was already extracted to `main` by the owner on the same day (`73e60cbe`), which excludes the mesh plane **by name**; four named items remain |
| `product-a-e2e-engine` | 271 | 2026-06-23 (`e1a177a4`) | Strict ancestor of the above. Same engine-side relay work + the nvpn plane + host-operator NAT/UPnP tooling + a real off-LAN/5G E2E evidence record | **SALVAGE** | high | Same `73e60cbe` extraction; what stays unique is mostly the part that was refused on purpose, plus three genuinely absent items |
| `spike/nvpn-slirp` | 22 | 2026-05-27 (`3e3086c3`) | Time-boxed feasibility spike: can a mesh daemon hold a tunnel inside a Firecracker microVM on slirp4netns? 810-line measurement report + a guest-kernel TUN build | **SALVAGE** | high | The kernel work is on `main` in a strictly better form; the *findings* — 79 min of failed builds — exist nowhere. Salvage docs only, no code |
| `zain/b-matrix-cells` | 17 | 2026-08-02 (`dc958791`) | Per-claw VPN T1 datapath measurement week: two real defects still live on `main`, dev telemetry, four QA cell reports | **SALVAGE** | high | Two production-path defect fixes are not on `main`; the rest is host-pinned scratch and one superseded signer |
| `jaime/b2-t1-traffic-driver` | 10 | 2026-08-01 (`40845301`) | The T1/T2 UDP traffic-driver harness and the three defect fixes it found | **SALVAGE** | high | Real work, but this **ref** is a strict patch-id prefix of `zain/b-matrix-cells` — land from the sibling, delete this ref after |
| `zain/g3-ffi` | 4 | 2026-08-04 (`0a130fee`) | The full G1→G2→G3 stack: iOS/macOS packet-flow shim, frame-addressed session mode, and the bridge tunnel control surface | **SALVAGE** | high | G1+G2 are the approved bytes and this is their only remote copy; the G3 tip carries a self-issued-ACL defect fixed only on an unpushed local branch |
| `zain/g2-session-core` | 3 | 2026-08-03 (`9872019d`) | G1 + G2: `AddressAssignmentMode`, `open_with_addrs`, collision scan, host assignability, reserved-range rejection | **LAND** | high | Absent from `main` by every route and merges clean; but it is a SHA-identical prefix of `g3-ffi`, so land the *content*, not this ref |
| `zain/g1-flowshim` | 1 | 2026-08-03 (`7645989e`) | One additive 783-line module: `FlowShim`, a callback→readiness adapter over a `socketpair(2)`, 9 tests | **LAND** | high | Compiled and tested against `e60bad85` by the investigator: 23/23 green. `main` has no callback-driven `PollablePacketInterface` by any route |
| `feat/household-machine-roster-currency-v1` | 1 | 2026-07-29 (`c204d0fc`) | Machine roster currency / device admission authority draft | **DROP** | high | Totally contained in `#402` (`b75ab636`): every public item of both roster modules is on `main`, which has more |
| `docs/t1-datapath-pump-redesign-followup` | 1 | 2026-07-08 (`0eb9a65c`) | A followup doc asking for the T1 pump redesign | **DROP** | high | The remedy shipped (`#300/#301/#302`, pump landed via `#413`); keeping the doc actively misinforms by documenting T2 as open |
| `codex/pair-device-uri` | 1 | 2026-05-13 (`1042094d`) | `GET /bootstrap/pair-device-uri` + 2 tests | **DROP** | high | Re-met independently by `#411` and extended by `#405`; landing it would register a second route on the same path |
| `ci/phase0-authority-pin-tests` | 1 | 2026-07-15 (`ac41f30c`) | Phase-0 authority pin regression tests | **DROP** | high | Rejected **for placement**, not staleness — it edits harnesses inside the base-owned authority root; `#349` re-landed the same four teeth outside it |
| `review/pr340-preview` *(local ref, not on origin)* | — | — | Stale local mirror of `e8684c25` | **DROP the local ref only** | high | Byte-identical to the head of **OPEN PR #340**; delete the local ref, never anything remote named "pr340" |

**Confidence.** Every investigator reported high confidence and each verdict rests on commands
recorded in the investigation. Two places where the evidence is thinner than the rest, stated
rather than smoothed over:

- **`product-a-e2e-engine`, on *why* the host-operator modules were left behind.** The two
  `core-rs` modules were mesh-free and existed six days before the 2026-06-24 extraction, and the
  extraction message enumerates what it took and names no `core-rs` module. The investigator reads
  that as scope-trimming (engine data path only) rather than a boundary refusal — and flagged
  explicitly that this is *inferred intent, not a quotation*. It matters, because it is the
  difference between "not yet ported" and "deliberately rejected". Treat it as open.
- **`review/*` sibling refs.** The investigator reported three further stale mirrors
  (`phase0-preview-v4`, `pr339-bootstrap-v2`, `pr339-bootstrap-v4`). Re-measured on 2026-08-06,
  `git for-each-ref refs/remotes/review` in this checkout lists **only** `pr340-preview`. Local-only
  refs differ per machine; check each one against `origin` before touching it.

## 4. What must happen next, per LAND / SALVAGE branch

Ordered by urgency, not by branch size.

### 4.1 URGENT — push `khai/g1-g3-recompose` (one command, near-zero risk)

`khai/g1-g3-recompose` @ `32ea0f85` exists **only as a local branch on one machine**.
`git ls-remote --heads origin 'refs/heads/khai/*'` returns only `khai/g1-g3-phase0-arm-v2` and
`khai/s2-copossession` — the recompose is not there.

It contains the four `zain/g*` commits at identical SHAs **plus two commits that exist on no remote
at all**: `117a13f1` "derive VPN ACL from credential" and `e65292a5` "bind ACL to authenticated
credential". Those two are the security-load-bearing half of the delivery. On `zain/g3-ffi` the
bridge fabricates its authorization key from a hardcoded scalar and hardcoded identity strings, then
grants that same key to a fresh ACL — the gate authorizes a key it just issued to itself, so the
`Unauthorized` path is unreachable. The successor replaces it with a key derived from the
authenticated credential and adds a source-guard test asserting the fixture helper is absent from
production source.

**Today, if that machine's disk is lost, the only surviving copy of this slice is the defective
one.** Pushing the branch is read-only with respect to `main` and blocks nothing.

### 4.2 The G-stack (`zain/g1-flowshim`, `g2-session-core`, `g3-ffi`) — half a day + an owner ceremony

One strictly linear chain (`g1 ⊂ g2 ⊂ g3`, same SHAs), merge base `05a51603` (`#414`, 2026-08-02).
`main` has touched none of the payload files since, and both the branch and the recompose
`merge-tree` clean onto `e60bad85`.

- **Land the recompose, not the individual branches.** Splitting G2 out now would fork an already
  approved delivery.
- **`g1-flowshim` and `g2-session-core` are ref-level redundant** and can be deleted with zero
  content loss — **on the condition that `g3-ffi` is preserved**, since until the recompose is
  pushed `g3-ffi` is the sole remote copy of `44f605f1`, `9872019d` and `0a130fee`.
- **The existing arm is stale.** OPEN PR #421 pins `armed_from_base_sha = aa3f4caa` and an expected
  head-tree OID; `main` has moved 157 commits since. Phase-0 anti-replay binds base SHA + expected
  head tree + generation, so that arm **cannot be consumed**. Relanding needs: rebuild the recompose
  on today's `main` (mechanical), re-run the crate gates against `e60bad85` (the "54 tests / clippy
  clean" claims were measured on 2026-08-03 against the old base), then close or supersede #421 and
  cut a fresh arm. **Steps 3 and 4 are owner-only.**
- Two small carried defects to fix while there: G1's commit body claims a prerequisite commit that
  is not on `main` and describes a buffer size `main` does not have — the test passes anyway, but
  the sentence will send the next reader hunting a missing commit; and `cargo clippy -p
  tunnel-wire-rs --all-targets` fails on one `type_complexity` in G1's test module (CI's actual
  scope is `--workspace` without `--all-targets`, which is clean — negative control run on pristine
  `main`).
- **Scope honesty for the PR body:** G1 lands with zero production callers (its consumer is G3), and
  it covers packet atomicity and counted overflow but **not** cancellation or teardown. Say so
  rather than letting a reviewer discover it.
- Note the near-miss that will otherwise be rediscovered as a duplicate: **`TunnelHandle` already
  exists on `main`** in `household-rs/src/claw_share.rs` as an unrelated Share transport hint. Same
  identifier, different crate, different capability. Grepping the name alone gives a false "main
  already has this".

### 4.3 `zain/b-matrix-cells` (+ `jaime/b2-t1-traffic-driver`) — four small pieces, ~2–3 days

Land **from `zain/b-matrix-cells`**: `git cherry origin/zain/b-matrix-cells
origin/jaime/b2-t1-traffic-driver` is empty, so the `jaime` ref carries nothing its sibling lacks,
while the sibling adds seven commits including the four QA cell reports. **Do not delete the
`jaime` ref before the sibling is adjudicated** — the two must be judged together or the work is
lost twice. Do **not** land the branch as one PR.

1. **"Oversized local packet is a counted drop, never fatal"** (~120 lines, no conflict, highest
   value). Verified still live on `main` `e60bad85`: `tunnel-wire-rs/src/pollable_pump.rs` builds
   `interface_read_buf: vec![0; max_accepted_packet_len + 1]`, `claw_vpn_pollable_pump.rs` passes
   `CLAW_VPN_V1_INNER_MTU` (= 1250), and no `claw_vpn` module sets an MTU on the tun/utun anywhere —
   so the interface carries the platform default (~1500) into a 1251-byte buffer. On macOS the utun
   decoder returns `InvalidData` when the packet exceeds the destination buffer and the pump's
   interface→relay arm turns any read error into a **fatal** stop. One ordinary 1252–1500-byte local
   packet kills the datapath instead of becoming a counted policy drop. **Land this before the T1
   datapath is mounted in production, not after.** While there, decide about
   `server-rs/src/claw_vpn_packet_pump.rs`, which has the identical derivation and is **not** fixed
   by the branch — fix it too or write the residue down.
2. **"Cancel-safe dev runner tunnel pipe"** (~60 lines, conflicts, hand re-application). Verified
   still live: `t1-iptunnel-dev-runner-rs/src/main.rs` still has `frame = recv_frame(&mut tunnel_r)`
   inline as a `tokio::select!` arm with no `pin!`, while `main`'s own production pipe in
   `household-rs/src/claw_share_data_tunnel.rs` carries a "CANCEL SAFETY (load-bearing; do not
   inline this back into the select!)" comment and pins. `recv_frame` is two sequential reads; a
   sibling arm winning drops it mid-frame and the next read consumes body bytes as a length.
   **Consequence, and it is a direct cause of the two months of churn: every T1 rate measurement
   above a few hundred pps taken before 2026-08-01 was instrument error, not product behaviour.**
   Measured: ~700 pps × 1200 B lost 99.97 % and died within ~28 frames before the fix; 30000/30000
   with zero loss after.
3. **Docs-only PR — the four QA cell reports** (highest value per byte for the owner's actual
   complaint, zero build risk). Two edits are mandatory: (a) a header on each saying "manual live
   run on named hosts, not re-runnable in CI, the VERDE is scoped by the LIMIT sections below" —
   the tip commit's subject line says "VERDE" and the reports themselves explicitly forbid the
   reading it invites ("This is NOT the Phase-3 Tailscale-free proof… citing it as *proved without
   Tailscale* is wrong"; "L1 VERDE != L2"); (b) the reports cross-reference a B-cell matrix
   (`B1–B11`, "§3.4 items 1–7") **that exists nowhere in the repo on any branch** — `main`'s
   per-claw VPN plan §6 defines a different `T1–T19` matrix. Either write the B-matrix down or
   strip the dangling references.
4. **Optional, owner call:** the Python UDP traffic driver + its unit tests (the only genuinely
   reusable harness — no host paths, JSON output) and the pump telemetry counters. Worth it only
   if T1 cells resume; they block nothing.

**Explicit drops from this branch:** the `e2e-rs` household-PoP signer — it implements the signer
contract `main`'s own M1 runbook marks legacy and BLOCKED, and stores a P-256 secret scalar as hex
in a plain file against the V1 requirement that the signer obtain private material from its own
approved secure store. Route it to the owner separately if wanted; "a software owner-PoP key
generated on first use" is an owner-authority question, not a rebase question. Also drop the
host-pinned cell shell scripts (absolute store paths, machine-specific home directories, hardcoded
keys and addresses, and an internal inconsistency between two of them); their only durable content
is the operator traps, already quoted in the reports. Note also that CI hard-fails on any new
`*.sh` under `scripts/` outside a 10-entry allowlist — landing the shell harnesses needs an
allowlist entry, which is a policy call.

### 4.4 `spike/nvpn-slirp` — ~30 minutes, documentation only

**No code from this branch should land.** The kernel work is already on `main` in a strictly better
form (same source tarball, same hash pin, same TUN force-enable loop, plus a wider kexec-disable
loop, post-`olddefconfig` fail-closed assertions the spike lacks, and a regression guard test the
spike never wrote). The two harness scripts are pinned to one host and already rotted. The rootfs
install of the third-party mesh binary belongs to the fenced-off track.

1. **Copy the 810-line report verbatim** to a dated archive path under `docs/`, with a five-line
   header: measured 2026-05-27, superseded on the kernel by `98bc864e`, retained as evidence and
   **not** as a plan. The report cites a file in a developer's home directory outside the repository
   for its root-cause analysis — inline those two paragraphs or the citation dies with the machine.
2. **Three lines into the kernel derivation's header comment** — see §5, item 1. This is the one
   whose absence costs real money again.

State in the archive header that the 0 %-loss result **authorizes nothing**. It is a closed
measurement of a fenced-off track.

### 4.5 `product-a-membership` and `product-a-e2e-engine` — one owner question, then act

These two are one decision: `git rev-list --count origin/product-a-membership..origin/product-a-e2e-engine`
→ **0**, so `e2e-engine` is a strict ancestor and whatever is decided for `membership` decides it.

**Do not reopen either as a PR.** A two-dot tree diff shows 755 files / 66,748 insertions /
**273,033 deletions** — `main` holds a quarter-million lines the branch tree does not. Merging is a
rewrite, not a merge. The keeper half was already extracted deliberately on 2026-06-24 (`73e60cbe`,
59 files / 35,250 insertions) whose message reads, verbatim: *"Mesh-free extraction + engine mount
of the community relay … Explicitly EXCLUDES the nvpn mesh-L3 (Plane 3)."* `main` has since
**evolved** that code past the branch — the shared relay_stream files are all larger on `main`,
which also carries a fail-closed guard the branch lacks.

**Tier 1 — do now, ~1 hour, it is a live security debt on `main`:** the mesh-write-authority
followup doc plus its one row in the followups index. It is the **only** part of the branch's tip
commit that did not reach `main`; the two code doc-comments from that same commit did. Its claim was
re-verified against today's `main`: the mesh write-authority check is still single-key and still
runs only inside the gossip ingest wrapper, while the mesh log store's `append` / `ingest_remote` /
`project` carry no intrinsic authority check. The two coupled risks become load-bearing the moment a
second engine replicates group/publish. **Re-anchor the citations to symbol names** — the doc cites
branch-tree line numbers that do not resolve on `main`.

**Tier 2 and Tier 3 are gated on one question the agents must not answer alone:**

> **Is a user-hosted community relay still a product direction?** `main` today ships only the
> hosted Share relay.

- **If yes** — Tier 2 (~2 days): port the host-operator network-readiness and port-mapping modules
  (~2,058 lines, 28 tests, mesh-free; `main` has **zero** UPnP / NAT-PMP / PCP / readiness code by
  any spelling). The only new manifest line is a dependency `main` already carries as a workspace
  dep and already uses. Leave the owner-gated router-mutation endpoint out — that is a separate
  security review, and the model module is deliberately I/O-free precisely so it can land without
  one. Land the reachability probe honestly labelled: it runs **from** the host, which is the wrong
  direction for proving one's own inbound reachability. Tier 3 (~30 min): rescue the live-state and
  productization docs as dated historical evidence — see §5 item 2 for the redaction requirement,
  which is **not optional**.
- **If no** — salvage Tier 1 alone and delete both branches.

**Drop outright, so nobody re-analyses them:** the mesh daemon supervisor crate, the claw-side mesh
agent crate, the PTY helper crate, the launchd owner runtime and its binaries, the roster publisher,
the whole transit/catalog/offer family, the LAN path-hints module (superseded by `main`'s Bonjour
modules — different mechanism, different names), the recovery-ladder module (superseded by `main`'s
WebAuthn recovery + Shamir modules), the two Nix deployment modules, the packaging shell scripts,
and the entire bootstrap ops tree. Every one is the mesh-L3 plane or its deployment harness, which
`main`'s own per-claw VPN plan §10 states in writing it is **not** resurrecting, and which `main`'s
blocking Lane C graph gate would reject on sight. Also drop the branch's QA gate harness: its
recorded "iOS Unit Tests PASS" and "SwiftPM Tests PASS" rows run Rust crate tests — rescuing it
would import a misleading green.

One item **is** worth pulling from `product-a-e2e-engine` independently of the relay question: the
autonomous confirm-or-revert Nix module and its two scripts (~268 lines of shell, arm a sentinel
before a remote `nixos-rebuild switch`, auto-confirm when connectivity returns healthy, else roll
back to the recorded known-good generation). It has nothing to do with the VPN, `main` has no
equivalent, and the repo already operates remote Linux hosts. **It must be smoked on a real remote
box before it is trusted** — deliberately break connectivity and confirm the rollback fires. A
rollback mechanism that has never rolled back is a claim, not a mechanism, and this one runs
unattended on a box nobody can reach.

## 5. Knowledge to rescue — findings that must outlive their branch

These are the parts that cost real time to learn and that no code carries. **Write them into a doc
even where the branch is dropped**, or they will be re-learned at full price. The nvpn-slirp spike
is the archetype: 22 commits, ~79 minutes of build wall-time, and the entire durable value is four
sentences.

1. **A downstream kernel config applied to mainline source builds fine and then panics at boot.**
   The Firecracker guest-kernel config must stay the mainline-derived one. A distro-downstream
   config applied to mainline source compiles cleanly and dies at `VFS: Cannot open root device
   "vda"` — virtio-blk discovery never fires. Two full builds (~45 min) were spent proving this.
   `main`'s derivation comment today says *which* config to use and never says *why*, so a future
   agent "cleaning up" the config has nothing stopping it. → Three lines into that header comment.
2. **The kexec-disable in the guest kernel is a toolchain workaround, not a policy.** The purgatory
   link fails on an undefined symbol under the current nixpkgs GCC because the upstream CI builds
   with a much older GCC that is no longer packaged. Firecracker never kexecs inside a guest, so
   disabling it is functionally a no-op. `main`'s comment states the symptom only.
3. **slirp4netns was never the obstacle.** Outbound UDP *and* TCP transit it cleanly — the
   "TCP-only" reputation applies solely to inbound host-forwarding. Measured end state inside a real
   microVM: tunnel device present, mesh up, data plane direct over UDP through slirp NAT, and 1200
   of 1200 pings received over ten minutes, 0 % loss, better than the bare-namespace control. **If
   the mesh track is ever revived, this sentence saves the third spike.**
4. **The mesh daemon has no auto-recovery from underlay perturbation.** Killing the userspace
   network stack, restarting the daemon, or flapping the tap device all left the mesh dead while
   status still reported peers reachable. Cause, read from upstream source: network-change detection
   is fingerprint-gated on interface/address/gateway identity, not on link state. That — not the
   transport — is what a revival would have to solve first.
5. **The community relay was proven on real hardware, once, and the record exists nowhere else.**
   A box was physically relocated to a third party's home, ran a public relay on a real WAN address,
   and a guest dialled it off-LAN and then from a phone on 5G behind carrier CGNAT: PTY marker
   echoed in about five seconds, identical byte fingerprints on both runs through a blind splice
   with no token, payload or address logged. `main` holds **recipes** for this proof — the equivalent
   runbook says of itself that the hardware run "is a deploy step" — but no **record** of it having
   passed. Equally important is what the same document says it did **not** prove: the dev mint
   self-signs so there was no real owner proof-of-possession, the site was a fail-closed placeholder,
   there was no membership, and the shell ran on the host rather than inside the VM.
   **Redaction is mandatory and is not a formality:** the repository is public and those documents
   contain a third party's home network — WAN address, LAN subnet and gateway, a hardware address,
   a mesh address, and the phone's carrier egress addresses. The branch already being pushed is not
   a licence; promoting it to `main` and to every clone is a fresh decision about someone else's
   data. Redact to shapes and keep the topology argument, which is the part that carries meaning.
   The companion gap-analysis doc cites ~40 branch-tree file:line coordinates, several in files that
   do not exist on `main` at all — strip to filenames and symbols before landing.
6. **Two transport libraries were evaluated for the relay and not adopted.** Keep the two spike
   READMEs as a one-paragraph decision record with the versions and the relay-capability model
   already worked out; drop the sources and the lockfiles and add neither to any workspace.
7. **A rejected design is not the same as a stale one.** The Phase-0 authority-pin branch still
   applies cleanly to `main` today, which is exactly the trap: a future agent will read "clean apply"
   as "safe to land". It was rejected for **placement** — it modifies harnesses inside the base-owned
   Phase-0 authority root — and the replacement deliberately re-landed the same four teeth outside
   that root. Landing it would re-introduce the rejected shape and require an authority re-pin.
8. **Two supersessions here happened by a different mechanism with different names**, and a symbol
   grep would have reported "not superseded, keep the branch" for both: the LAN path-hints module
   was replaced by the Bonjour browser/publisher/trust modules, and the recovery-ladder module by
   the WebAuthn recovery anchor/consume plus Shamir sharding. When a branch module greps to zero on
   `main`, the next question is *what capability did it provide, and does main provide it under
   another name*.
9. **The mesh plane is fenced out of `main` by a blocking CI gate, not merely unmerged.** Outside
   comments and docs there is exactly one reference to it on `main`, and it is inside the graph gate
   whose stated job is enforcing that boundary. `main` built the successor architecture instead —
   a native in-repo tunnel/mesh-session/device-key stack with a package-graph guard. Landing the
   supervisor or agent crates would fail `main`'s own gate. This is a written product decision
   (per-claw VPN plan §10: *"reuses the nvpn effort's learnings (kernel TUN recipe) but is **not** a
   resurrection of the nvpn L3 mesh"*), not an oversight.
10. **A "VERDE" in a commit subject is not a scope.** The T1 cell reports each carry LIMIT sections
    that contradict the headline they ship under. Any rescued evidence doc must state its scope in
    the same breath as its verdict, or the verdict travels alone and gets cited as more than it is.

## 6. How to re-run this triage

Refresh the map; do not rebuild it. Roughly ten minutes.

```sh
# 0. Fresh view of the remote. Prune, or you will triage refs that no longer exist.
git fetch --all --prune
git rev-parse origin/main                       # record this in the header, always
git ls-remote --heads origin | wc -l            # branches that actually exist right now

# 1. Graph-merged (this is the instrument that MISSES squash-merges — never use it alone)
git branch -r --merged origin/main | grep -v ' -> ' | wc -l

# 2. Per-branch classification. Patch-id + PR state, together.
for b in $(git branch -r --format='%(refname:short)' | grep -v ' -> ' | grep -v '^origin/main$'); do
  n=$(git cherry origin/main "$b" 2>/dev/null | grep -c '^+')
  pr=$(gh pr list --state all --head "${b#origin/}" --json number,state \
        --jq '[.[]|"#\(.number):\(.state)"]|join(",")')
  d=$(git log -1 --format='%cd' --date=short "$b")
  printf '%-55s uniq=%-4s last=%s pr=%s\n' "$b" "$n" "$d" "${pr:-none}"
done

# 3. Disposable if ANY of these holds:
#      uniq == 0                     (patch-id identical, includes rebased work)
#      pr shows a MERGED state       (squash-merge: git branch --merged cannot see it)
#      the tip is an ancestor of main:  git merge-base --is-ancestor <tip> origin/main

# 4. For anything left, before investigating the diff:
git merge-base origin/main <branch>             # how far back it forked
git rev-list --count <base>..origin/main        # how far main moved under it
git diff --shortstat origin/main <branch>       # TWO dots: tree vs tree.
                                                # A huge deletion count means merging is a rewrite.
git merge-tree --write-tree origin/main <branch>   # rc=0 clean; a clean automerge is NOT
                                                   # evidence the content is still correct

# 5. Does main already have the capability, possibly under another name?
git grep -l '<Symbol>' origin/main -- admin/    # zero hits is a starting point, not an answer
git log --oneline --reverse origin/main -- <path>   # when did main first get this file, and via which PR
git ls-tree --name-only origin/main <dir>       # compare crate/module inventories, not just symbols

# 6. Local-only refs. These exist on one machine and are invisible to everyone else.
git for-each-ref --format='%(refname) %(objectname:short)' refs/remotes | grep -v '^refs/remotes/origin/'
git branch --format='%(refname:short) %(objectname:short)'   # local branches with no remote copy
```

Then update this file: bump the header SHA and date, add or amend rows, and **keep the superseded
row with its old date** rather than overwriting it. The history of what was decided is the point.

### Standing cautions for whoever executes a sweep

- **Never delete a remote ref by matching a PR number in its name.** The stale mirror
  `review/pr340-preview` is byte-identical to the head of OPEN PR #340, whose branch is named
  something else entirely. Delete local refs with `git update-ref -d refs/remotes/<name>`; verify
  every remote deletion against `gh pr list --state open` first.
- **Do not delete `zain/g3-ffi` until `khai/g1-g3-recompose` is pushed.** It is the sole remote copy
  of three of the four G-stack commits.
- **Do not delete `jaime/b2-t1-traffic-driver` until `zain/b-matrix-cells` is adjudicated.** They
  must be judged together.
- **`product-a-e2e-engine` is a strict ancestor of `product-a-membership`** — one decision covers
  both.
