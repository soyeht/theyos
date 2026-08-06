# Product A — device⇄device mesh VPN plan

**Status: plan only.** This document authorizes no code, no branch, no flag,
no deploy, and no activation. It is the third Product A VPN plan and the first
one whose subject is device⇄device connectivity; the two existing plans named
that subject as a **non-goal**, and §9.3 records how that record has been
amended — by its own author, in place — rather than quietly overwritten, along
with the obligation the amendment hands back to this document.

Authored 2026-08-06. Every measurement of **code** below was taken against
**`origin/main = e60bad85`** ("Merge pull request #422: mesh-session lifecycle,
D1 runtime facade, nonce-ledger bridge, Lane C graph gate", Thu Aug 6 02:08:16
2026 -0300), read with `git show origin/main:<path>` and
`git grep <pat> origin/main -- <paths>`. No number here was taken from a
working tree. Where a number depends on a counting predicate, the predicate is
stated with it.

<!-- doc-freshness-anchor
measured: 2026-08-06
sha: e60bad85313eb39c9a000a29852bde1a944e425e
paths:
  - admin/rust/mesh-session-core-rs/
  - admin/rust/mesh-session-control-model-rs/
  - admin/rust/mesh-session-runtime-rs/
  - admin/rust/m1-household-mesh-smoke-rs/
  - admin/rust/household-rs/src/mesh_*.rs
  - admin/rust/keystore-rs/src/mesh_session_bridge.rs
  - admin/rust/server-rs/src/household_listener.rs
  - admin/rust/tunnel-wire-rs/
  - admin/rust/Cargo.toml
-->

**One exception, stated because it is the kind of thing that rots silently.**
The four sibling plans this document cross-references — per-claw, mobile,
capacity, tiers — are **uncommitted working-tree documents**. Every reference to
them is therefore by *document and section*, never by line number (R10), and
their figures are attributed to them rather than re-derived here (§3.4.1(d)). A
reader checking this document against `origin/main` alone will not find them.
As of 2026-08-06 all five are edited as one set rather than by five concurrent
authors, and the "which document is normative for what" block below is what
keeps that true after the set is split up again.

**Revision note, 2026-08-06.** Four corrections were made to an earlier
revision after review, and each is marked in place rather than silently
absorbed: §1.8 item 3 and R4 (a fail-closed claim measured against the wrong
one of two same-named types — **withdrawn**, the risk widened back); §1.3.2,
§5.1 and Phase 0 (an exit criterion the proposed additions could not deliver —
**rewritten**, with the three-feature trap named as its own work item);
§3.4.1 and Phase 5 (a decision the capacity plan assigns here and this plan had
left silent — **recorded**); §2 (three plans defining one mode three ways —
**aligned** to per-claw §12 as canonical).

**Aliases.** Neutral aliases only; the repository is public. No real hostnames,
IPs outside documentation ranges, device names, account names, relay endpoints,
paths, or secrets appear here or in any evidence derived from this plan.

| alias | meaning |
|---|---|
| `Household-H` | the household root of trust and its signed roster |
| `Machine-A` | a macOS machine already admitted to `Household-H` (machine profile) |
| `Machine-B` | a Linux machine already admitted to `Household-H` (machine profile) |
| `Phone-P` | the owner's phone, owner-device profile (`DeviceCert → PersonCert → HouseholdRoot`) |
| `Relay-R` | the blind rendezvous/splice relay operated for Soyeht |
| `Signal-S` | the rendezvous signalling surface described by the R0b contract |
| `Overlay-U` | the overlay network the **user** brings and operates — a personal WireGuard, Tailscale, or equivalent. The mode is **user-operated overlay transport**, defined in per-claw §12, which is canonical (§2); `Overlay-U` is the single alias for it across all five plans |

## Which document is normative for what

Settled 2026-08-06 across the five Product A / cost plans, so that a shared
concept is resolved **once**. A document that is not normative for a row cites
that row's owner and does not restate it; where two documents disagree, the
defect is in the non-normative one. This block is the mechanism R10 was missing.

| shared concept | normative document |
|---|---|
| transport modes — the Soyeht datapath vs **user-operated overlay transport** (`Overlay-U`) | `docs/product-a-per-claw-vpn-plan.md` **§12** (per-mode security table: §12.3) |
| entitlement chokepoint | `docs/soyeht-tiers-and-entitlement-plan.md` **§5.0** |
| relay cost, capacity, and the limits a session runs under | `docs/soyeht-relay-vps-capacity-and-cost-plan.md` |
| device⇄device track | **this document** |
| iOS client state | `docs/product-a-mobile-claw-control-vpn-plan.md` |

---

## 1. Where we are today

### 1.1 The central fact

There is a large, carefully reviewed device⇄device session stack in this
repository, and **the engine does not reference it**.

```
git grep -n 'mesh_session' origin/main -- admin/rust/server-rs/src/
  -> no output
git grep -n 'mesh-session' origin/main -- admin/rust/server-rs/src/
  -> admin/rust/server-rs/src/household_listener.rs:2100:
       for excluded in ["mesh-session-core-rs", "mesh-session-control-model-rs"] {
```

The single hit is a string literal inside a `#[cfg(test)]` directory-walk
assertion. The production engine has no call site, no import, and no type
reference into the mesh-session stack.

That is not the whole gap. Inside the stack itself, **no public API can produce
a session**. `run_responder_handshake` and `run_initiator_handshake` in
`admin/rust/mesh-session-core-rs/src/auth_state_machine.rs` are both
`pub(crate)`; so are `LocalIdentity`, `LocalCheckpoint`, `ExpectedResponder`,
and `wire::DeadlineBoundedIo`. `ActiveMeshSession::send_data` is `pub` and
unreachable, because nothing public returns an `ActiveMeshSession`. The module
doc states the reason verbatim:

> if either function (or the types they take) were `pub`, any external crate
> could call them directly with an invented identity and obtain a genuine
> `ActiveMeshSession`, without even needing a peer to misbehave.

The crate carries `#![allow(dead_code)]` and says a plain build "has no
production caller for anything in this module yet."

**The keystone.** `mesh-session-runtime-rs/src/d1_admission.rs` states, in its
own module doc, that **no real `H: RevocableMeshSession` exists anywhere in
this workspace**. `RegistryD1Admission::new` needs a `Weak<H>` handle;
`MeshSessionRegistry::new` is called from exactly two sites, both inside
`#[cfg(test)]` blocks (`mesh_session_registry.rs:2409` and `:3495`). The
runtime facade is therefore unreachable *by construction*, not merely unwired.

### 1.2 What exists, measured

Predicate for every row: all tracked `.rs` files under the path at
`origin/main = e60bad85`; lines by `wc -l`; tests by
`grep -c '#\[test\]'`. Attribute counts and a `cargo test` run do not agree
exactly (doctests, per-target splits); the counting predicate is stated so the
number is reproducible, not so it can be compared against a run.

| object | lines | `#[test]` | lib source compiled by CI | tests executed by CI |
|---|---|---|---|---|
| `admin/rust/mesh-session-core-rs/` | 14,732 | 207 | yes | **no** |
| `admin/rust/mesh-session-control-model-rs/` | 11,960 | 138 | yes | **no** |
| `admin/rust/mesh-session-runtime-rs/` | 1,587 | 29 | yes (feature on) | **no** |
| `admin/rust/keystore-rs/src/mesh_session_bridge.rs` | 1,269 | 15 | yes (feature on) | **no** |
| `admin/rust/household-rs/src/mesh_session_registry.rs` | 5,215 | 71 | yes (default) | **yes** |
| `admin/rust/household-rs/src/mesh_intent_nonce_ledger.rs` | 3,633 | 43 | yes (default) | **yes** |
| `admin/rust/tunnel-wire-rs/` | 2,814 | 13 | yes (default) | **yes** |
| `admin/rust/m1-household-mesh-smoke-rs/` | 2,677 | 41 | yes (default) | **yes** |

Also load-bearing and already wired into the engine:
`household-rs/src/machine_roster_store.rs` (8,886 lines) and
`machine_roster_authority.rs` (9,726 lines), reached from production handlers
via `MachineRosterCoordinator::from_validated_household`
(`handlers_household_roster.rs:300`, `:531`; `owner_site_roster_adapter.rs:172`,
`:430`).

### 1.3 Correcting a number that is in circulation

A statement is circulating in planning material that the two excluded crates
are **"26,694 lines that never compile or run in CI."**

**The size itself is wrong, and the measurement settles it: 26,692.** The
predicate, stated so the number is reproducible rather than quotable: the sum of
`wc -l` over every **tracked `.rs` file** under
`admin/rust/mesh-session-core-rs/` and
`admin/rust/mesh-session-control-model-rs/` at
`origin/main = e60bad85` — **28 files, 26,692 lines** (14,732 + 11,960, the two
rows in §1.2's table, which is where the split lives). `26,694` matches no path
set tried at this SHA and is not reproduced anywhere in this document.
`docs/product-a-mobile-claw-control-vpn-plan.md` §0.4 carries the same measured
figure; the two documents agree, and the same predicate is stated in both.
(Note the two crates hold **34** tracked files in all; the six non-`.rs` ones —
manifests and lockfiles — are outside the predicate.)

The rest of the sentence is wrong in a more interesting way. The half about
running is right. The half about compiling is **wrong for the libraries** — they
are
compile-checked on both runners — and quoting it would justify either deleting
the workspace exclusion as dead weight, which would *lose* coverage that
exists, or funding a re-integration slice whose stated benefit has already
shipped.

It is, however, **right for exactly one file**, and for a reason nobody had
found when the sentence was written: `tests/model_invariants.rs` (6,137 lines,
134 tests) is inlined behind *three simultaneous* features while CI's loop
passes one at a time, so it is neither compiled nor run (§1.3.2). The correct
replacement sentence is at the end of this section; it is more specific than
either the original claim or the first correction of it.

What the exclusion actually is:

```
admin/rust/Cargo.toml
  exclude = ["mesh-session-control-model-rs", "mesh-session-core-rs"]
```

with the manifest's own reason: both crates declare their own `[workspace]`,
and once `keystore-rs` path-depends on one, cargo would otherwise report
"multiple workspace roots found in the same workspace". The exclusion keeps
them **detached AND depended-upon**.

What CI actually compiles. `.github/workflows/backend-ci.yml` has a step
"Feature surface compiles (all targets)" whose (package, feature) pair list is
*derived* from `cargo metadata --no-deps`, never hand-written, and which runs
`cargo check --locked -p <pkg> --all-targets --features <feat>` for every
non-default feature. That list contains `keystore-rs mesh-session`.
`keystore-rs` reaches both excluded crates from that one feature:

```
keystore-rs/Cargo.toml:12
  mesh-session = [..., "dep:mesh-session-core-rs"]          # real path dependency
                                                            # (dep at Cargo.toml:25)

keystore-rs/src/lib.rs:56-57, :89
  #[cfg(feature = "mesh-session")]
  #[path = "../../mesh-session-control-model-rs/src/lib.rs"]
  mod d4_inline;                                            # the same files, not a copy
```

So the **library sources** of both crates are compile-checked on both the Linux
and macOS runners on every push and PR touching `admin/rust/**`.

What CI never does is **execute** their tests. Exhaustively, `cargo test` appears
in **three distinct forms**, at five call sites (the first two forms once per
runner):

```
cargo test --workspace -- --test-threads=1                                     # :134, :225
cargo test -p household-rs --features mesh-session-runtime \
  --test compile_fail_peer_expectation -- --test-threads=1                     # :149, :240
cargo test -p claw-share-bridge-rs                                             # :343
```

`--workspace` cannot reach an excluded package. `#[cfg(test)]` is not set for a
crate built as a dependency, so the inline test modules are not even compiled —
which, per §1.3.1, is the whole of `mesh-session-core-rs`'s 207 tests.

Proxy split, labelled as a proxy (per file: lines from the first line matching
`^#\[cfg(test)\]` to EOF, plus whole files under a `tests/` directory) —
approximately **12,179 non-test lines compile** and approximately **14,513
lines of test region do not**.

#### 1.3.1 Where the 345 tests physically live — and why it decides everything in §5

The two crates are not symmetric, and the asymmetry is the whole reason a
single CI addition cannot cover both. Predicate: every tracked `.rs` file under
each crate at `origin/main`, `grep -c '#\[test\]'` per file.

```
for d in mesh-session-core-rs mesh-session-control-model-rs; do
  for f in $(git ls-tree -r --name-only origin/main -- admin/rust/$d | grep '\.rs$'); do
    printf '%s\t%s\n' "$(git show origin/main:$f | grep -c '#\[test\]')" "$f"
  done
done
```

| crate | count | where | reachability |
|---|---|---|---|
| `mesh-session-core-rs` | **207** | **all inline `#[cfg(test)]` in `src/`**; the crate has no `tests/` directory at all | `#[cfg(test)]` is never set for a crate built as a *dependency*, so **no feature combination and no `-p` invocation from any dependent reaches them.** Only a `cargo test` whose manifest *is* that crate |
| `mesh-session-control-model-rs` | **138** | **all under `tests/`**: 134 in `tests/model_invariants.rs` (6,137 lines), 4 in `tests/cas_multiprocess.rs`; **zero** in `src/` | the 134 are reachable through `keystore-rs`'s `#[path]` co-location, but only behind three simultaneous features (§1.3.2); the 4 need `CARGO_BIN_EXE_*`, which cargo injects only for integration targets, so they stay in the standalone crate |

#### 1.3.2 The three-feature trap — 6,137 lines that do not even compile

`keystore-rs/src/lib.rs:110–116` inlines the 134-test file:

```
#[cfg(all(
    test,
    feature = "mesh-session",
    feature = "test-support",
    feature = "roster-sync-unratified"
))]
#[path = "../../mesh-session-control-model-rs/tests/model_invariants.rs"]
mod d4_reds;
```

Four conditions at once. The CI feature-surface loop satisfies **one feature per
invocation**, by construction:

```
.github/workflows/backend-ci.yml:121-129   (Linux)  and  :212-220  (macOS)
  cargo metadata --no-deps --format-version 1 \
    | jq -r '.packages[] | . as $p | ($p.features|keys[]) | select(.!="default") | "\($p.name)\t\(.)"' \
    | sort >/tmp/feature-surface.tsv
  while IFS=$'\t' read -r pkg feat; do
    cargo check --locked -p "${pkg}" --all-targets --features "${feat}"
  done </tmp/feature-surface.tsv
```

`keystore-rs` contributes **three separate rows** to that TSV — `mesh-session`,
`test-support`, `roster-sync-unratified` (`keystore-rs/Cargo.toml:12`, `:16`,
`:17`) — and no row enables the other two. So `d4_reds`'s `cfg` is never
satisfied: **`model_invariants.rs` is neither compiled nor executed, and no
single-feature invocation can ever reach it.** This is structural, not an
oversight in the loop: a loop that iterates single features cannot express a
conjunction.

Two precisions that keep this claim from being over-read:

- The repository **does** contain one three-feature invocation:
  `admin/rust/scripts/graph-gate/run_gate.sh:249`, `c2-clippy-meshtests`,
  `cargo clippy -p keystore-rs --all-targets --features
  mesh-session,test-support,roster-sync-unratified`. It sits in PHASE 3, which
  is reached only in `full` mode; CI invokes `structural`
  (`backend-ci.yml:370`), which exits at `run_gate.sh:227` before PHASE 3. And
  even in `full` mode it is `clippy`, which **compiles** the target and never
  executes it. So the file's *compilation* is measurable today by a script CI
  does not call; its *execution* is measurable by nothing.
- `keystore-rs/Cargo.toml:13–15` states the intent of the two extra features
  verbatim: *"They stay OFF: the gated D4 surface (fault injection,
  `seed_for_test`, RosterSync) must not exist in any keystore build."* Any
  proposal to enable all three is therefore not a free CI addition — it is a
  change with a stated reason against it, and §5.1 O1 has to answer that reason
  rather than route around it.

**The true statement this plan uses: the library sources of both excluded
crates compile on both runners on every relevant PR; their tests execute on no
machine, on any schedule; and `model_invariants.rs` — 6,137 lines, 134 of the
345 tests — does not even compile, for the three-feature reason above.**

### 1.4 The three feature switches

| crate | feature | default | effect when off |
|---|---|---|---|
| `mesh-session-runtime-rs` | `mesh-session-runtime` | `[]` | every `mod`/`pub use` in `src/lib.rs` is `#[cfg]`-gated, so the crate builds to an empty lib |
| `household-rs` | `mesh-session-runtime` | `[]` | gates only the D1 projection surface in `machine_roster_authority.rs` (all 16 `cfg` sites are in that one file) |
| `keystore-rs` | `mesh-session` | no `default` key | `mesh_session_bridge` and `d4_inline` do not exist |

The important consequence, and it corrects a second common reading: the
household half is **not** dark. `mesh_session_registry.rs` and
`mesh_intent_nonce_ledger.rs` are bare `pub mod` declarations in
`household-rs/src/lib.rs` with no `cfg` — they compile and their tests run
under the default `cargo test --workspace`. The live-revocation registry, the
piece this track depends on most, is already shipping inside the engine's own
library.

### 1.5 What the M1 smoke proves, and what it must never be quoted for

`m1-household-mesh-smoke-rs` is a **Tailscale-transport diagnostic**. Tailscale
is not one check in it; it is the entire transport premise, enforced at three
independent layers, one of which lives in the shipped engine:

1. `runner.rs` stops the run `Blocked` unless `local_tailnet_ipv4()` returns an
   address satisfying `bits & 0xffc0_0000 == 0x6440_0000`.
2. `PeerEndpoint::parse` rejects any host that is not a literal Tailscale
   address (CGNAT IPv4 or the Tailscale ULA prefix) and requires
   `scheme == "http"` — plaintext, with confidentiality delegated to WireGuard.
3. `post_reachability_echo` in `server-rs/src/handlers_bootstrap.rs` returns
   `403` unless `peer.ip().is_loopback() || is_tailnet_ip(peer.ip())`.

Its dependency list is `base64, clap, libc, rand, serde, serde_json, ureq,
url`. There is no edge to `household-rs`, `server-rs`, `tunnel-wire-rs`, or any
mesh crate, and `tests/workspace_boundary.rs` exists to keep it that way.

The binary's own `DRY_RUN_PLAN` states the limit verbatim:

> The /machines query is access-controlled, but its reachability bool is not an
> authenticated identity or presence claim. The echo is unauthenticated.
> Neither result is membership, authority, DeviceCert presence, or VerifiedMesh
> evidence.

and the echo handler's doc adds that a successful echo "MUST NOT create a
`LocalAddressOwnership::VerifiedMesh` fact." The runbook documents a bounded
false positive: a poisoned address cache pointing at any other host running the
echo endpoint.

**DS0 (stated first because it is the easiest mistake to make): no existing or
future M1 smoke run counts toward any acceptance criterion in this plan.** M1
is Tailscale-connectivity evidence plus owner-PoP-authorization evidence, and
contains zero Soyeht-datapath evidence.

### 1.6 What is already built and directly reusable

- **Real TUN/utun open primitives.** `server-rs/src/claw_vpn_macos_utun.rs`
  (562 lines, `com.apple.net.utun_control` kernel-control socket) and
  `claw_vpn_linux_tun.rs` (459 lines, `/dev/net/tun` + `TUNSETIFF`). Both
  already implement `ClawVpnPollablePacketInterface` — they already plug into
  the neutral pump. Both module docs say they are "intentionally not wired into
  bootstrap, bins, relay runtime, route installation, storage, or flags."
- **A claw-free datapath crate.** `tunnel-wire-rs` has dependencies
  `ciborium, libc, serde, thiserror, tokio, tracing` and *deliberately* no edge
  to `household-rs`; its manifest says "Adding `household-rs` here is the RED
  mutant." `pollable_pump.rs` (536 lines) sees the product through exactly one
  trait, `PacketPolicyPort`, with two methods; the module doc says the crate
  "never learns any of it exists." `frame_stream.rs` (581 lines) is a stateful
  non-blocking `[4-byte BE len][payload]` codec; `worker_pool.rs` (723 lines)
  is a parked-worker pool over an opaque `PoolWorkItem`.
- **A transport adapter that is nearly there.**
  `impl DeadlineBoundedIo for std::net::TcpStream` already exists in
  `mesh-session-core-rs/src/wire.rs`, and
  `PrevalidatedIngress::admit_at_accept(stream, IngressEvidence, CeremonyBudget)`
  is already `pub` (`ingress.rs:219`). The trait itself is `pub(crate)`, so the
  adapter is a visibility decision, not a research problem.
- **A ratified identity contract.** `docs/owner-mesh-rendezvous/r0a-…-v1.md`
  (539 lines) fixes **D1 = DUAL-CHAIN**: machine profile for `Machine-A` and
  `Machine-B`, owner-device profile for `Phone-P` via
  `DeviceCert → PersonCert → HouseholdRoot`. `Phone-P` does not enter
  `HouseholdRecord.members`, does not change `shamir_k`/`shamir_n`, and gets no
  `MachineCert`. **D4** limits v1 cardinality to the current `k=n=2` household
  plus one owner phone; a third machine is explicitly deferred.
- **A signalling contract, on paper.** `r0b-protocol-contract-v1.1-final.md`
  (254 lines): rendezvous carries address hints only — "NÃO transporta
  identidade, chave, autorização, nem datapath" — with a CSPRNG ≥128-bit
  single-use id, 20 s TTL, and a fail-closed TLS requirement on the
  distribution channel.

### 1.7 What the protocol core actually is

One authentication ceremony: 3 Noise-XX flights, then a signed intent record,
then 5 signed auth frames, yielding an `ActiveMeshSession`. Responder sequence,
verbatim from the driver's doc:

```
Idle → Handshaking → SendingProofR → AwaitingIntent → AwaitingProofI
     → SendingFinalConfirm → AwaitingActivate → Active
```

Wire type bytes (`auth_frames.rs`, `intent.rs`, `post_active.rs`):

| byte | record |
|---|---|
| `0x01`–`0x05` | `ProofR`, `ProofI`, `FinalConfirm`, `Activate`, `ActivateAck` |
| `0x06` | `SignedMeshConnectionIntent`, domain `soyeht/mesh-connection-intent/v1` — deliberately **not** an `AuthFrame` variant |
| `0x07` | `SignedMeshConnectionCapability` — reserved, unimplemented anywhere |
| `0x10` / `0x20` / `0x30` / `0x40` | post-Active `DATA` (opaque bytes) / `REVOKE_NOTICE` / `CLOSE` / `REKEY` |

Post-Active traffic is real code: `send_data`, `receive_data`,
`close_gracefully`, `notify_revoked_and_close` are all `pub`. The session's
private `expires_at` is the **minimum** of the checkpoint's `not_after`, both
delegations' `not_after`, the caller's `lease_expires_at`, the ingress expiry,
and the intent's `not_after`.

### 1.8 Four declared-but-unbuilt seams

`mesh-session-runtime-rs/src/signer_seam.rs` enumerates them, each with a "what
would close this". All four are constructor parameters of
`keystore_rs::mesh_session_bridge::{MeshSessionBridgeSigner, BridgeGenerationResolver}::new_internal`:

1. **`SignatureVerifier`** — blocked on mesh-core freezing the
   delegation-signing byte layout. The shipped verifier is
   `NoVerifierConfigured` (`delegation.rs:343`), which fails unconditionally.
2. **A real `cell::open` call site** — blocked by the `pub(crate)`-through-
   `d4_inline` visibility wall *and* by `open` taking `spy: Arc<OrderSpy>`,
   whose own doc ties it to test inspection with no documented production
   value.
3. **A real `max_ttl`** — `DelegationPolicy::production()` returns
   `max_ttl: 0`, rejecting every delegation. What is missing is a
   `configured(max_ttl)` constructor and a measured value to pass it.

   **Correction, re-measured 2026-08-06 at `origin/main = e60bad85` after a
   reviewer disputed it. An earlier revision of this plan claimed here, and in
   R4, that the injectable `DelegationPolicy::test` constructor is
   `#[cfg(test)]`-gated and that the fail-closed floor is therefore
   compiler-enforced. That claim was measured against the wrong type and is
   withdrawn.** There are **two** distinct types named `DelegationPolicy`:

   ```
   git grep -n 'struct DelegationPolicy' origin/main -- admin/rust/
     admin/rust/mesh-session-control-model-rs/src/validator.rs:124
     admin/rust/mesh-session-core-rs/src/delegation.rs:369

   git show origin/main:admin/rust/mesh-session-core-rs/src/delegation.rs \
     | grep -n 'max_ttl: u64,\|pub fn production\|pub fn test\|#\[cfg(test)\]'
     370:    max_ttl: u64,                       # private field
     384:    #[cfg(test)]
     385:    pub fn test(max_ttl: u64) -> Self {

   git show origin/main:admin/rust/mesh-session-control-model-rs/src/validator.rs \
     | grep -n 'pub max_ttl\|pub fn production\|pub fn test\|#\[cfg(test)\]'
     125:    pub max_ttl: u64,                   # PUBLIC field
     132:    pub fn production() -> Self {
     136:    pub fn test(max_ttl: u64) -> Self {  # NO cfg on this line or above it
   ```

   The `#[cfg(test)]` gate is real — on the **`mesh-session-core-rs`** type. The
   type at *this* seam is the other one. `signer_seam.rs:65` names
   `crate::validator::DelegationPolicy { max_ttl: u64 }`;
   `keystore-rs/src/mesh_session_bridge.rs:51` imports
   `crate::validator::{DelegationPolicy, …}`; and `crate::validator` inside
   `keystore-rs` *is* the control-model source, co-located by
   `keystore-rs/src/lib.rs:56–57` (`#[path =
   "../../mesh-session-control-model-rs/src/lib.rs"]`), declared `mod d4_inline;`
   at `:89`, and re-exported `pub(crate) use d4_inline::*;` at `:92`.

   For that type the floor is **not** compiler-enforced, on three counts:

   - `pub fn test(max_ttl)` carries no `cfg`, so it exists in every build;
   - `max_ttl` is a **`pub` field**, so `DelegationPolicy { max_ttl: 86_400 }`
     is a legal struct literal and would bypass the constructor even if `test`
     were gated;
   - and `mesh-session-control-model-rs/src/lib.rs:167` is `pub mod validator;`,
     so any crate that can name the type can do both.

   **Conclusion: at this seam `production()` is a correct default that a correct
   caller calls. Nothing makes an incorrect caller fail to compile.** Enforcing
   it would mean making `max_ttl` private on the control-model type and gating
   or deleting its `test` constructor — a change inside a crate this plan does
   not own, so it is filed as a risk and an open question (R4, Q7), not assumed.

   This is the "two types, one name" failure mode. The lesson recorded for the
   next reader: `git grep 'struct <Name>'` **before** asserting a property of
   `<Name>`; a property measured on one definition says nothing about the other.
4. **A `generation: NonZeroU64` source** — a bare caller-supplied scalar with
   no fetch or derivation anywhere in the workspace.

---

## 2. Two transport modes, both first-class

The owner authorized two product modes on 2026-08-06.

**Canonical definition, and where it lives.** Five plans landed together and
**each defined the user-supplied-transport mode in its own words**, all citing
the same owner decision. That is one decision under several names, which is how
a mode ends up meaning several things. **`docs/product-a-per-claw-vpn-plan.md`
§12, "User-operated overlay transport (a supported mode)", is the canonical
treatment** — it is the most developed of them, it carries the per-mode
security table (its §12.3, S1–S12 with a verdict per property), and it holds
the single registry of the retired spellings. This document
**adopts** that definition and its vocabulary rather than restating them, and
§2.1–§2.3 below carry only what is specific to device⇄device and absent there.

Two vocabulary alignments, made here so the documents can be read together:

- The mode is called **"user-operated overlay transport"**, per §12's heading,
  and the network the user operates is **`Overlay-U`** — one name and one alias,
  now used by all five plans; the retired spellings are enumerated once, in §12,
  and not here. This document's shorthand "mode 2" names **the same mode**; where
  two documents disagree in wording, §12 governs.
- Revocation in that mode is **"authorization-complete but not necessarily
  reachability-complete"** — per-claw §12.3 S5's phrase, adopted verbatim into
  DS6 below, replacing this plan's earlier independent phrasing of the same
  property.

### 2.1 The modes

- **Mode 1 — Soyeht-owned datapath.** `Machine-A`, `Machine-B` and `Phone-P`
  carry packets over a Soyeht-owned tunnel: a device-scoped wire on
  `tunnel-wire-rs` mechanics, keyed by the mesh-session ceremony, rendezvoused
  via `Signal-S` and (when direct connectivity is unavailable) spliced by the
  blind `Relay-R`.
- **Mode 2 — user-operated overlay transport.** As defined in per-claw §12: the
  user selects an overlay they operate themselves — a personal WireGuard,
  Tailscale, or equivalent (`Overlay-U`) — and Soyeht rides it. Soyeht opens no
  tunnel interface, installs no route, and runs no relay for that user. Per-claw
  §12.2's summary applies unchanged with "claw" read as "peer device": *"What we
  still own on that path is the control plane … What we do not own is packet
  carriage."* Per-claw §12.4's non-goals (we do not install, configure, operate,
  recommend a vendor for, hold credentials for, troubleshoot, proxy through, or
  read the ACL of the user's overlay) apply here verbatim and are **not**
  restated in this document's §10.

**The one place device⇄device differs from per-claw §12, and it is a real
difference.** Per-claw §12.3 records **S9 (anti-spoof + no forwarding) as
`NO`** — the significant loss — because with no claw agent in the path nothing
performs the two-address policy check, and the claw is reachable at whatever
scope the user's overlay grants. In device⇄device mode 2 the equivalent
property is **DS9**, and it is lost the same way and for the same reason: no
Soyeht `PacketPolicyPort` is in the path, so *"no forwarding, ever"* is
unenforced and each device is reachable at its overlay's scope. DS9 is therefore
labelled *(mode 1)* below, and the loss is stated rather than inherited
silently. Anyone reading DS9 as a both-modes property has made per-claw §12.3's
S9 mistake in this document's vocabulary.

Mode selection is an explicit user choice. **There is no automatic fallback in
either direction** (see DS7).

### 2.2 What Soyeht owns in each mode

| capability | mode 1 | mode 2 | where it lives today |
|---|---|---|---|
| household identity chains (`MachineCert`/`PersonCert`/`DeviceCert` → `HouseholdRoot`) | Soyeht | Soyeht | `machine_cert.rs`, `member_identity.rs` — shipped |
| signed roster + checkpoint chain + revocation currency | Soyeht | Soyeht | `machine_roster_store.rs` (8,886 lines), `machine_roster_authority.rs` (9,726) — wired into the engine |
| owner-PoP authorization for control operations | Soyeht | Soyeht | `household_auth::authorize_request` — shipped |
| durable mesh intent nonce ledger (anti-replay) | Soyeht | Soyeht | `mesh_intent_nonce_ledger.rs` (3,633 lines) — shipped, tests run |
| session admission + live revocation registry | Soyeht | Soyeht | `mesh_session_registry.rs` (5,215 lines) — shipped, tests run; **no production caller** |
| session key agreement (Noise-XX + signed intent) | Soyeht | **undecided — Q9** | `mesh-session-core-rs` — built, unreachable |
| rendezvous / address discovery | Soyeht (`Signal-S`) | **`Overlay-U`** | R0b contract; **no implementation** |
| NAT traversal | Soyeht (relay-first; see §3.4) | **`Overlay-U`** | **does not exist in this repository** |
| packet carriage | Soyeht | **`Overlay-U`** | `tunnel-wire-rs` + TUN/utun primitives, unwired |
| tunnel interface + route scope on the device | Soyeht | **`Overlay-U`** | TUN/utun primitives, unwired |
| enforcement of revocation at the packet layer | Soyeht | **nobody** — see DS6 | — |

The shape this table describes is not a fiction. The identity/authority half is
**over 18,600 lines already running in the engine**; the transport half is the
part that does not exist. Mode 2 is the mode where the half that exists is the
whole product.

**How this table maps onto per-claw §12.3's S1–S12**, so the two are read as one
model and not two. This table is the *ownership* view (who owns each capability
in each mode); §12.3 is the *property* view (which security property survives).
They are the same finding twice:

| this table's row | per-claw §12.3 | verdict there |
|---|---|---|
| session key agreement / end-to-end confidentiality | **S3** E2E encryption | *Not ours* — the overlay's own encryption applies; we do not perform, verify or attest it |
| enforcement of revocation at the packet layer | **S5** rotation/revocation | *Yes, with a caveat* — **authorization-complete but not necessarily reachability-complete** |
| household identity chains, owner-PoP, session admission | **S1**, **S2**, **S10** | *Yes* — control-plane checks, independent of who carries packets |
| (no row — device-mesh equivalent is DS9) | **S9** anti-spoof + no forwarding | **NO** — the significant loss; see §2.1 |
| tunnel interface + route scope | **S12** route scope | *Not applicable, and that is the hazard* |
| audit (DS12) | **S8** auditability | *Yes*, except byte counters that depended on our pump |

Where a row here and a verdict there could be read as disagreeing, **§12.3
governs** and this row is the defect.

### 2.3 The measurement this document adds to per-claw §12.1

Per-claw §12.1 already resolves the four contradicting sentences across the
repository, including the mobile plan's, in a table headed *"The contradiction,
stated rather than deleted."* That resolution is **not restated here.** What
follows is only the measurement behind one row of it — the mobile plan's
sentence — which this document took and §12.1 cites the verdict of rather than
the evidence.

`docs/product-a-mobile-claw-control-vpn-plan.md` **used to say**, verbatim:

> Tailscale may be used for developer administration only; it is not part of
> the shipped VPN datapath.

**That sentence no longer stands in that form.** Per-claw §12.1's verdict was
*superseded as a product-scope statement, owned by that plan's rewrite*, and the
rewrite has since landed: the mobile plan **splits** the sentence under
"Transport choice — two claims that were conflated" into clause (a) *our
datapath depends on no third-party overlay* (kept, still true) and clause (b)
*the user may not choose one* (superseded). Quote the split, not the original.
The measurement below is what made it superseded — the sentence was **already
false about the control plane in shipped code**, and was when it was written:

- `InterfaceClass` (`server-rs/src/household_listener.rs:33`) is a closed enum
  `{Loopback, Lan, Tailscale, Mesh}`. `HouseholdExposurePolicy::allows` grants
  `Tailscale` in **every** bootstrap state including `Uninitialized` and
  `ReadyForNaming`; `Mesh` is granted only in
  `NamedAwaitingPair`/`Ready`/`Recovering`.
- `POST /bootstrap/initialize` and `GET /pair-machine/anchor-handoff` return
  `tailnet_required` (403) unless the source IP is a Tailnet address
  (`household-rs/src/bootstrap_error.rs:99`,
  `server-rs/src/handlers_pair_machine.rs:904`, contract fixture
  `bootstrap_error_codes.json`, e2e assertions in
  `e2e-rs/tests/scenario_b_iphone_first.rs:391/414/433`).
- The engine steers the phone to its own Tailnet IPv4 (`current_tailnet_ipv4`)
  in the claim ACK **specifically so the source IP passes that guard**
  (`handlers_bootstrap.rs:473`, `:831`).

Household onboarding on a Mac + phone therefore already depends on Tailscale in
shipped code.

The sentence conflated two different claims. This plan splits them:

- **Anti-fallback (kept, strengthened, DS7).** Soyeht's own datapath must never
  silently fall back to `Overlay-U`, LAN, or any other path. Mode-1 evidence
  must prove the Soyeht tunnel carried the traffic. This is the property the
  original E2E evidence rule was actually protecting.
- **User-selected transport (new, DS8).** A user who deliberately selects
  `Overlay-U` as their transport is a supported, first-class user. Mode 2 is a
  product mode with its own test rows and its own stated limits, not an
  unsupported workaround.

The owner's decision on record: *"o usuario pode usar o soyeht entre devices com
o tailscale … o tailscale eh uma alternativa que o user pode escolher."*

The mobile plan's rewrite did **scope** the old sentence rather than delete it,
so the record shows an invariant that was split, not one that was dropped. Its
clause (a) is this plan's DS7 in the mobile plan's vocabulary; its clause (b) is
DS8.

---

## 3. Architecture

### 3.1 Identity and admission — shared, unchanged

Device⇄device admission uses the R0a dual-chain model exactly as ratified. No
new identity type, no new root, no analogical authority for `Phone-P`. The
ceremony is the existing one (§1.7). The three real, independently-owned pieces
`RegistryD1Admission::reserve_pending` already composes stay as they are:
`MachineRosterCoordinator::current_snapshot` →
`SealedBinding::from_membership_key` →
`MeshSessionRegistry::try_preauthorize_before`.

### 3.2 The device wire — a second product on `tunnel-wire-rs`, not a generalisation

`tunnel-wire-rs/src/tunnel_wire.rs` enumerates exactly what stayed product-side
when the neutral crate was extracted, and why. The device⇄device product
mirrors that list rather than widening the neutral crate:

| claw-side item today | device-mesh equivalent | why not shared |
|---|---|---|
| `HEALTH_PROBE` value `claw-share/health/v1` | a device-scoped, domain-separated probe value | sharing a probe value makes two products indistinguishable on the wire |
| `TunnelAck` (carries `mesh_ipv6` + claw `session_id`) | a device ack carrying device-mesh session identity | a neutral type with a field only an authority can fill is not neutral |
| the strict `0x17` `NetworkSettings` mirrors | a device-mesh settings mirror with its own strict decoder | the settings body is sealed; only the owning product may construct or interpret one |
| `AuthTimeout` / `Rejected` / `TokenRejected` / `HealthMismatch` | a closed device-mesh error enum wrapping `WireError` | the mechanic/authority line runs *inside* the old error enum |

What is reused verbatim: `PollablePump` and `PacketPolicyPort`,
`NonblockingFrameReader`/`Writer`, `worker_pool`, `TunnelFrame` framing and its
redacted `Debug`, and `MeshIpv4`'s route-scope rule.

This preserves the property the compiler currently enforces — `tunnel-wire-rs`
has no `household-rs` edge, so no `pub use` chain can reach claw authority from
it — and avoids reopening a settled review.

### 3.3 Datapath before ceremony

The datapath is nearly done and the ceremony is blocked on frozen-spec
decisions that do not exist yet (§1.8). Sequencing the ceremony first would
stall a track whose most valuable missing evidence — **real IP between two
devices over a Soyeht-owned path** — needs no new protocol at all.

The dev-gated proof (Phase 2) opens a utun on `Machine-A` and a tun on
`Machine-B`, connects one TCP socket between the two engines, and pumps IPv4
through a device-scoped `PacketPolicyPort`. Every component already exists:
`claw_vpn_macos_utun.rs` and `claw_vpn_linux_tun.rs` already implement the
pollable interface trait; `PollablePump` + `frame_stream` already move framed
packets over a non-blocking fd pair. It is gated exactly as `dev_t1_datapath` is
gated today (`server-rs/Cargo.toml:188`,
`t1-iptunnel-dev-runner-rs/Cargo.toml:22`).

This proof is **not** an authorization result. Until the ceremony lands, its
peer authentication is a dev fixture, and DS3 says so in the invariant itself.

### 3.4 Rendezvous and NAT traversal — the largest unbuilt surface

There is **no NAT traversal anywhere in this repository**: no STUN, no ICE, no
UDP hole punching. The per-claw plan's answer was a public relay; that answer
is available here too, and `Relay-R` already exists as a blind splicer with
abuse limits.

Rendezvous exists only on paper. The R0b doc says so about its own types:
`ClawVpnMobileRendezvousToken`/`RendezvousToken` in
`claw_vpn_mobile_state.rs:470` are "modelo puro … SEM wiring de produção". A
separate `claw_share_rendezvous_token::RendezvousToken` *is* wired, but for the
Share relay_stream path, not for mesh.

**Decision, taken under the owner's delegation of micro-decisions:** mode 1 v1
is **relay-first**. `Machine-A`, `Machine-B` and `Phone-P` all dial outbound to
`Relay-R`; no inbound listener is required on any device. This is the choice
that reuses the already-rented relay host, needs no new protocol surface, and
works for 100% of NAT pairs rather than ~70%.

#### 3.4.1 The direct-path decision the capacity plan assigns to this document

`docs/soyeht-relay-vps-capacity-and-cost-plan.md` §6 L0 assigns one specific
resolution to this plan by name — *"The device↔device mesh plan owns that
resolution; this document supplies the cost case for it"* — and its checkpoint
C10 says **"Silence is not a decision."** An earlier revision of this plan made
direct-path a bare non-goal and recorded no reasoning. That was the silence C10
forbids. The reasoning is recorded here.

**(a) The scope resolution, done the way the capacity plan asks — by scope, not
by deletion.** The always-relay decision stands on a privacy argument, quoted
verbatim from `docs/soyeht-share-apple-like-plan.md` (§7, the paragraph headed
*"Always-relay stands for this cycle"*):

> A direct path would reveal the owner's **residential IP to the guest**,
> contradicting the product promise that a friend uses the app without entering
> the owner's home; the blind relay keeps both ends mutually anonymous.

That sentence is **kept, and remains correct for Share**, whose counterparty is
a stranger guest. **Its premise does not hold for device⇄device mode 1.** Both
endpoints are `Machine-A`/`Machine-B`/`Phone-P` — devices of the *same*
household principal, already mutually authenticated through the same
`HouseholdRoot`. There is no third party to whom an address could be disclosed:
the disclosure the Share sentence prevents is owner→guest, and here both sides
are the owner. Nothing is deleted; the sentence is scoped to the counterparty
class it was written about.

The Share paragraph's *cost* half also inverts, and this must be said rather
than borrowed: it reads *"the cost argument is weak in both directions … the
whole prize is roughly US$21 → US$7/month at 1 M registered."* That arithmetic
is concurrency-bound and Share-shaped. The capacity plan's §6 L0 measures the
VPN workload, which is **egress-bound**, and puts the same lever at ~US$7,246 →
~US$2,200/month at 100,000 users — *"No other lever in this document is within
an order of magnitude of that."* The Share plan's own S4 trigger (*"Only if
measured egress exceeds 50% of the 1 TB allowance"*) is, per capacity §4.7,
crossed by a VPN workload at **~48 users**.

**(b) The decision, with its date and its trigger — not a non-goal.**
Direct-path candidate exchange (reflexive candidates, hole punching) is
**deferred, not declined**. §10 still lists it, but no longer as a bare item:
that bullet now carries the trigger and the obligation to record an outcome
rather than re-defer. Concretely:

- **v1 ships relay-first.** Relay-R stays provisioned regardless: capacity §6 L0
  records that ~30% of pairs fail hole punching, so direct-first *reduces the
  bill, it does not remove the layer.* Sequencing a 100%-coverage path first is
  therefore not a cost decision at all — it is the layer that must exist either
  way.
- **The deferral expires at the earlier of two events**, and whoever reaches one
  first must record the outcome against capacity C10 rather than re-defer:
  (i) mode-1 measured egress crossing 50% of one Relay-R node's monthly
  allowance — the capacity plan's own S4 trigger, ~48 mode-1 users; or
  (ii) **Phase 5 exit**, whichever comes first. At that point either the
  direct-path slice is scheduled, or a written decision states why an
  egress-bound workload will pay roughly 3× to keep always-relay.
- **What is not blocked — with one correction to how that reads here.** Capacity
  §6 L0 records that the *Share* signed offer is structurally ready for an
  additive direct-candidate field: two fields already use
  `#[serde(default, skip_serializing_if = "Option::is_none")]`, so an offer
  omitting the field encodes byte-identically to before the field existed,
  preserving canonical CBOR, the owner signature, and the cross-language
  fixtures. That removes the "we cannot change the offer" objection **for the
  Share/relay_stream path**. It does *not* transfer to device⇄device by
  adjacency: the device-mesh rendezvous is `Signal-S`, which has **no
  implementation and no wire type at all** (§1.6, §3.4). So for this track the
  honest statement is narrower — there is no frozen payload to be blocked *by*,
  and the direct-candidate field should be designed into `Signal-S` from the
  start rather than retrofitted. If Phase 5 lands `Signal-S` without a candidate
  field, this plan will have created the constraint it is currently claiming not
  to have.
- **What deferral costs, stated so it is not free:** every month of deferral
  past the trigger is a bill this plan chose. That is the trade, named.

**(c) What is *not* delegated.** Enabling direct-path for *stranger-facing
Share* is explicitly out of this document's scope — capacity §1 lists it in the
deferred column. This resolution covers device⇄device between one principal's
own devices and nothing else. A future reader must not lift it into the Share
path.

**(d) Provenance of the numbers.** `~48 users`, `~3×`, `~US$7,246 →
~US$2,200/month at 100,000`, and `70% ± 7.1%` are **the capacity and Share
plans' figures, not independently re-derived here.** This document takes them as
inputs to a decision and does not restate their derivation; if the capacity
plan's §4.7 model changes, this decision's trigger moves with it and §3.4.1 must
be re-read, not assumed still valid. The one thing this document does own is the
**scope** argument in (a), which depends on no number at all.

This is also the honest statement of why mode 2 is attractive: the single
largest engineering surface in mode 1 is exactly the surface a user's own
`Overlay-U` eliminates — and capacity §6 L0b prices that at zero marginal cost,
which is the same conclusion from the cost side.

### 3.5 Addressing

Device-mesh addressing must not collide with either neighbour:

- not `100.64.0.0/10` or the Tailscale ULA prefix — mode 2 coexistence, and
  `classify_local_address` already maps those to `InterfaceClass::Tailscale`;
- not the per-claw VPN pool — a device address must never be routable as a claw
  address, and vice versa;
- not `InterfaceClass::Mesh`'s existing range without an explicit decision, so
  the exposure policy in `household_listener.rs` stays legible.

The concrete prefix is an open question (§12 Q1) with the measurement that
settles it.

### 3.6 Cardinality

R0a's D4 limits v1 to the current `k=n=2` household: `Machine-A`, `Machine-B`,
and one owner phone `Phone-P`. **This plan stays inside that ratified scope.** A
third machine, N machines, or multiple phones require R0a to be amended first,
by its owners, not assumed by this document.

---

## 4. Security load-bearing points

Each point states the mode in which it holds. Where a property is true only in
mode 1, the invariant says so **in the invariant**, not in a footnote.

- **DS0 — M1 is not product evidence.** *(both modes)* No M1 smoke run, past or
  future, satisfies any acceptance criterion here. M1 proves Tailscale
  reachability plus owner-PoP authorization and has no dependency on any mesh,
  tunnel-wire, TUN, or Noise code.

- **DS1 — Admission is roster-backed, never self-asserted.** *(both modes)*
  Every session is admitted through `MeshSessionRegistry::try_preauthorize_before`
  against a current `RosterSnapshotView`. `run_responder_handshake` must not
  become `pub` without a sealed, roster-backed admission authority in the same
  change; making it `pub` alone reintroduces exactly the bypass its own doc
  describes, where a self-consistent fabricated identity yields a genuine
  `ActiveMeshSession` with no misbehaving peer required.

- **DS2 — Dual-chain identity, no analogical authority.** *(both modes)*
  `Machine-A`/`Machine-B` use the machine profile; `Phone-P` uses the
  owner-device profile. `Phone-P` never enters `HouseholdRecord.members`, never
  alters `shamir_k`/`shamir_n`, never receives a `MachineCert`.

- **DS3 — End-to-end confidentiality is Soyeht's only in mode 1.**
  *(mode 1 only)* In mode 1 the Noise session is end-to-end between devices and
  `Relay-R` never holds keys or plaintext. **In mode 2 confidentiality is
  `Overlay-U`'s WireGuard, and Soyeht neither provides nor verifies it** — this
  is per-claw §12.3's **S3** verdict (*"Not ours"*) in this document's
  vocabulary, and it must be stated to the user as *their* transport's property,
  never as ours. Until the ceremony is reachable (§1.1), the Phase-2 dev
  datapath has *no* peer authentication and its evidence is labelled
  accordingly.

  **Stated limit of this point, not smoothed over:** DS3 is written as though
  mode 2 carries no Soyeht session keying at all. Whether that is true depends
  on Q9 — whether the mesh-session ceremony runs *over* `Overlay-U` in mode 2,
  or whether mode 2 reduces the ceremony to admission only. If it runs, DS3's
  mode-2 clause is too strong and confidentiality is doubly provided. The
  document does not yet know which, and §2.2's row for session key agreement is
  marked undecided for the same reason.

- **DS4 — Replay is closed by a durable ledger.** *(both modes)* The intent
  record carries a 32-byte nonce and `not_after`; the durable
  `MeshIntentNonceLedger` is the anti-replay authority. `MayHaveTakenEffect` is
  never reclassified into `Committed`/`AlreadyConsumed`.

- **DS5 — Session lifetime is the minimum of its bounds.** *(both modes)*
  `ActiveMeshSession::expires_at` is the min of checkpoint `not_after`, both
  delegations' `not_after`, the caller's `lease_expires_at`, ingress expiry, and
  intent `not_after`. No caller may widen it.

- **DS6 — Revocation is enforcement in mode 1 and de-authorization in
  mode 2.** *(asymmetric — read the whole point)* In mode 1, a revoked session
  loses its `ForwardingGuard`, the pump stops moving its packets, and the peer
  loses IP reachability. **In mode 2, revocation is
  *authorization-complete but not necessarily reachability-complete*** — the
  phrase is adopted verbatim from per-claw §12.3 **S5**, replacing this
  document's earlier independent wording of the same property, so the two plans
  say it identically. Concretely: revoking stops Soyeht-mediated forwarding and
  session authorization, but the peer remains IP-reachable over `Overlay-U`,
  because Soyeht does not control that network. Per-claw §12.3 adds the
  obligation this plan adopts: *"this must be said in the product UI, not buried
  here."* The asymmetry must therefore appear in the product UI, in the audit
  record, and in any entitlement design that hangs off the same path (§7).

- **DS7 — No silent fallback, in either direction.** *(both modes)* A mode-1
  session that cannot establish must fail closed with a redacted error. It must
  never complete over `Overlay-U`, LAN, or the relay's control channel. A mode-2
  session must never silently open a Soyeht tunnel. Mode is an explicit,
  user-visible selection.

- **DS8 — Mode 2 is a supported mode with stated limits.** *(mode 2)* Soyeht
  owns identity, roster, revocation currency, owner-PoP authorization, naming,
  the nonce ledger, and session admission. Soyeht owns no packet, no route, no
  interface, and no relay. Any claim of parity with mode 1 is a defect; the
  limits in DS3, **DS6 and DS9** are part of the mode's definition. The
  canonical statement of the mode is per-claw §12, and its §12.3 closing
  requirement is adopted here: the UI *"must say which of these properties are
  provided by Soyeht and which by the user's own network"* — in this document's
  vocabulary the three that change hands are **DS3, DS9, and byte-level audit
  under DS12**.

- **DS9 — No forwarding, ever.** *(mode 1)* The device-mesh packet policy
  accepts only the session's own address pair in both directions. A device is
  never a router: LAN peers, other households' devices, claws, and the engine
  admin surface are unreachable through the device tunnel by construction.

- **DS10 — Device mesh and claw VPN are separate authorizations.** *(both
  modes)* A device⇄device grant never implies a claw grant and vice versa.
  `ClawVpnAclKey { member_id, device_pub, claw_id }` is the claw relation and
  must not grow a device-mesh dimension; the device-mesh relation is its own
  keyed record. Holding one and presenting it at the other's admission point is
  a fail-closed reject with a generic error.

- **DS11 — Fail-closed defaults survive wiring.** *(both modes)*
  `DelegationPolicy::production()` returns `max_ttl: 0` and rejects every
  delegation; `NoVerifierConfigured` fails every signature. Neither may be
  replaced by a value or verifier chosen to make a test pass. A real `max_ttl`
  arrives as a named, reviewed configuration change with the measurement behind
  it (§12 Q2), not as part of a wiring slice.
  **Enforcement status, measured 2026-08-06: this is a review obligation, not a
  compiler guarantee.** The type at the seam
  (`mesh-session-control-model-rs/src/validator.rs:124`) exposes `pub max_ttl`
  and an ungated `pub fn test(max_ttl)`, so `DelegationPolicy::test(86_400)` and
  the bare struct literal both compile in non-test code today. An earlier
  revision of this plan asserted the opposite, having measured the same-named
  type in `mesh-session-core-rs` instead; the full re-measurement and the
  commands are in §1.8 item 3, the widened risk is R4, and closing it is Q7.
  Reviewers of any delegation-path slice must check this by reading the diff —
  no gate will fail for them.

- **DS12 — Audit without value-echo.** *(both modes)* Session lifecycle events
  carry reason codes and neutral local identifiers only. Never packet payloads,
  never real addresses, never `session_id` in a formatter — `VpnNetworkSettings`
  and `TunnelFrame` already redact in `Debug`, and the device-mesh types must do
  the same. Mode is recorded on every event, so a mode-2 revocation is never
  read as a mode-1 enforcement.

- **DS13 — Cardinality stays inside the ratified contract.** *(both modes)*
  Two machines and one owner phone. Any wider claim requires R0a to be amended
  by its owners first.

---

## 5. Ordering: get the dark layer under measurement first

No readiness claim about `mesh-session-core-rs` or
`mesh-session-control-model-rs` means anything until their 345 tests run
somewhere. That comes before any slice that depends on them.

Two things had to be measured before this section could be written honestly, and
both are in §1.3.1–§1.3.2: **where** those tests physically live (the two crates
are not symmetric, and the asymmetry decides what a CI step can reach), and the
**three-feature trap** that makes 134 of them uncompilable by any invocation the
CI feature loop can express.

### 5.1 The additions, and exactly what each one covers

Corrected 2026-08-06. An earlier revision listed three additions and claimed
they delivered all 345 tests. They do not — the 207 in `mesh-session-core-rs`
are structurally out of reach of every one of them (§1.3.1), and O1 delivers
134 of the 138, not 138. The list below is what the additions actually cover,
with the residue named as its own work item.

| # | addition | tests it makes **execute** | measured caveat |
|---|---|---|---|
| O1 | `cargo test -p keystore-rs --features mesh-session,test-support,roster-sync-unratified` (from `admin/rust`) | **134** — `model_invariants.rs`, against the **co-located** instance `keystore-rs` actually compiles. This is the invocation the three-feature trap requires (§1.3.2): all four `cfg` conditions are satisfied at once, `test` by `cargo test` and the three features explicitly | **not caveat-free.** `keystore-rs/Cargo.toml:13–15` says the two extra features *"stay OFF: the gated D4 surface (fault injection, `seed_for_test`, RosterSync) must not exist in any keystore build."* O1 turns them on. That is defensible for a **test-profile** build and indefensible for anything shippable — the step must be a `cargo test` and must never become a `cargo build`/`check` whose artefact is consumed, and it must carry that sentence at the call site. See Q8 |
| O2 | `bash scripts/graph-gate/run_gate.sh full` (from `admin/rust`) | **0** — it compiles, it does not execute | PHASE 4 already enters both excluded crate directories as separate roots (`run_gate.sh:266–270`) and PHASE 3 already runs the three-feature clippy row (`:249`). CI runs only `structural` today (`backend-ci.yml:370`), which exits at `:227` before PHASE 3. Valuable as a **compile** gate for the excluded crates; it is not test execution and must not be reported as such |
| O3 | `cargo test -p mesh-session-runtime-rs --features mesh-session-runtime` | **29** — the runtime-facade tests, including the trybuild proof that `map_channel`'s match stays exhaustive | these 29 were never part of the 345; this closes a *different* gap. Today CI *compiles* that test target via the feature-surface `--all-targets` check but never executes it, so the proof that file was written for has never run |
| **O4** | two invocations inside each excluded crate's own root — `( cd admin/rust/mesh-session-core-rs && cargo test )` and `( … && cargo test --features test-support )`; `( cd admin/rust/mesh-session-control-model-rs && cargo test )` and `( … && cargo test --features test-support,roster-sync-unratified )` | **207 + 4** — core-rs's inline tests and control-model's `cas_multiprocess.rs` | **this is the work item the earlier revision was missing.** Both crates declare their own `[workspace]`, so no `-p` flag from `admin/rust` reaches them (`run_gate.sh:267–269` records the exact error: *"`cargo check -p mesh-session-core-rs` from `admin/rust` exits 101 'did not match any packages'"*). Entering the directory keeps the toolchain pin, because `admin/rust/rust-toolchain.toml` (channel `1.92.0`) is a parent of both. Each crate then has its own `Cargo.lock`, so `--locked` behaviour and cache reuse differ from the workspace steps — unmeasured, see Q8 |

O3 is a one-line addition next to the existing
`cargo test -p household-rs --features mesh-session-runtime --test compile_fail_peer_expectation`
step (`backend-ci.yml:149`, `:240`), which exists for exactly the same reason.

**Coverage arithmetic, stated so it cannot be rounded up:**
O1 = 134, O4 = 211 (207 + 4), total **345**. O2 = 0 executed. O3 = 29, outside
the 345. Note that O4's *two invocations per crate* are overlapping runs, not
additive ones — see Phase 0 exit criterion 2.
Nothing here executes the 207 without O4, and O4 is the addition that did not
exist in the earlier revision of this plan.

**Two limits on that arithmetic, so it is not read as more than it is.** First,
345 is an **attribute count** (`grep -c '#\[test\]'`), not a harness count; the
predicate is stated in §1.2 so the number is reproducible, not so it can be
compared against a run. Phase 0's exit asks for the *harness* counts to be
recorded, and they will differ — doctests and per-target splits are the known
reasons. Second, **how the 207 split across O4's two invocations is not
measured.** Only one file in `mesh-session-core-rs/src/` mentions
`feature = "test-support"` (`intent.rs`), which suggests the featureless run
carries nearly all of them — but "suggests" is an inference from a grep, and the
two runs' counts must be recorded separately rather than summed on faith.

### 5.2 The two-invocation trap that will otherwise disable O1 and O4

Every one of these crates must be run **twice** — once with no features, once
with its gated features on — because their `compile_fail` doctests are proofs
that the gated surface is **absent** and legitimately fail when the features are
on. `mesh-session-control-model-rs/src/lib.rs` carries 14 `compile_fail`
mentions; `mesh-session-core-rs/src/lib.rs` carries 2.

`mesh-session-control-model-rs/Cargo.toml` states the pattern in its own words,
and any CI step that lands should quote it at the call site rather than
paraphrase:

> The two properties are proven by two separate, explicit invocations:
> `cargo test` — closed surface; `cargo test --features
> test-support,roster-sync-unratified` — full suite

The same manifest also explains why `cargo test` alone runs **zero** integration
tests there: both `[[test]]` targets carry
`required-features = ["test-support", "roster-sync-unratified"]`.

A single-invocation CI step will look broken and get disabled by the next person
who sees it red. Any step that lands must carry that explanation at the call
site.

### 5.3 What ordering must NOT do

**Un-excluding the two crates is a security change wearing tidying's clothes.**
Two properties depend on the current shape and must both be named in any
proposal that touches `exclude`:

1. `keystore-rs`'s `#[path]` co-location exists because, across crates,
   `ControlRecordCell::acquire_for_sign_internal` is a private method (`E0624`).
   Working around that across a crate boundary was measured to force a
   guard-owning token onto the caller and stall `RevokeUrgent` for as long as
   that caller cared to hold it.
2. The exclusion is what keeps `D1MembershipKey::new_for_test` and
   `FaultInjectingCell` out of every default build.

Neither property is recoverable by "just adding them as members".

---

## 6. Phases

Every phase is default-off. No phase authorizes production activation, deploy,
or a flag flip; those remain separate, individually owner-authorized events.

### Phase 0 — measurement (this plan's prerequisite)

Land O1, O2, O3, **O4** (§5.1) with the two-invocation explanation (§5.2).
Re-pin the graph gate's `baseline-cf3969fd.json` and
`allowlist-mesh-session-runtime.txt` in the same change if the additions move
them, and record who owns that pin.

**Exit — rewritten 2026-08-06.** The earlier wording ("all 345
previously-unexecuted tests run on both runners on every PR") was not deliverable
by the additions that were listed, for the structural reasons in §1.3.1 and
§1.3.2. It is replaced by four separately-checkable criteria, each naming the
addition that delivers it and the count it delivers:

1. **O1 executes 134.** A `cargo test -p keystore-rs` step with all three
   features runs `model_invariants.rs` and reports a nonzero test count. The
   non-vacuity check is the count itself: today the file does not compile, so a
   step that prints `0 passed` has satisfied its `cfg` in name only. Record the
   count in the PR.
2. **O4 executes 211.** Both excluded crates run from their own roots, in both
   the featureless and the featured invocation, with **each run's count recorded
   separately**. The counts do **not** sum: the featured run is a superset of the
   featureless one for `mesh-session-core-rs` (the gate is `test-support`, and
   the ungated tests run in both), so the criterion is *the featured run covers
   the 207* and *the featureless run is nonzero and its `compile_fail` doctests
   pass* — those two runs answer different questions and neither substitutes for
   the other (§5.2). For `mesh-session-control-model-rs`, a plain `cargo test`
   reporting `0 tests` is the **expected** result, not a failure — both
   `[[test]]` targets are `required-features`-gated — and the step must say so at
   the call site, or it will be "fixed" by someone who reads zero as broken.
3. **O3 executes 29 and its trybuild proof runs at least once.**
4. **O2 keeps the boundary measurable.** The graph-gate summary line still shows
   `skip=0`, and PHASE 3 / PHASE 4 compile both excluded crates as separate
   roots.

**Which runners, and on which PRs.** O1, O3 and O4 belong in the two
`Build & Test (Rust / …)` jobs (`backend-ci.yml:29–31`, `:157–159`), so they run
on Linux and macOS. O2 today lives in the single-runner `validate-bridge` job
(`macos-15`, `backend-ci.yml:248–250`); moving or duplicating it is a decision
for whoever lands the step, and this plan does not pre-empt it. **"Both runners"
is a claim about O1/O3/O4 only until that decision is recorded.**

"Every PR" needs the same narrowing. `backend-ci.yml:15–25` filters
`pull_request` on paths, and `admin/rust/**` is the relevant entry — so these
steps run on every PR that touches Rust sources, and on **no** PR that touches
only `docs/`. That is correct behaviour, not a gap, but it means a plan document
alone can never turn this exit criterion green, and this plan is a document.

**Named work item, its own line, not folded into the above — WI-0a: the
three-feature trap.** `keystore-rs/src/lib.rs:110–116` gates 6,137 lines behind
`all(test, feature="mesh-session", feature="test-support",
feature="roster-sync-unratified")`, and the CI feature-surface loop
(`backend-ci.yml:125–129`, `:216–220`) iterates `pkg\tfeat` pairs one feature at
a time — a loop shape that **cannot express a conjunction**, so no amount of
adding features to the metadata-derived list will reach it. The invocation
required is exactly:

```
cd admin/rust && cargo test --locked -p keystore-rs \
  --features mesh-session,test-support,roster-sync-unratified
```

WI-0a is not "add a line to the loop"; it is "add a step **outside** the loop,
and add a comment inside the loop saying why a conjunction-gated target can
never appear there." Without the second half, the next person to audit feature
coverage will read the loop as exhaustive — which is how this file went
unmeasured in the first place. WI-0a must also answer Q8: the manifest says
those two features must not exist in any keystore build, and the step turns them
on.

### Phase 1 — the device-mesh wire

Add the four product-side items from §3.2 in a new device-mesh module: the
domain-separated probe value, the device ack, the settings mirror with its
strict decoder, and the closed error enum wrapping `WireError`. No change to
`tunnel-wire-rs` itself.

**Exit:** the new wire round-trips in unit tests, **and** the frozen claw/Share
vectors are unchanged and still green — proving the shipped bytes did not move.

Know where that guard actually lives before relying on it.
`tunnel-wire-rs/src/tunnel_wire.rs:37` cites
`tests/data/s0_claw_wire_vectors_v1.json`, but the file is
`admin/rust/household-rs/tests/data/s0_claw_wire_vectors_v1.json` and the only
consumer is an inline test in a *different crate*:
`household-rs/src/claw_share_data_tunnel.rs:1414`,
`s0_claw_wire_vectors_round_trip_byte_identical` (it builds the path at
`:1384`). Nothing in `tunnel-wire-rs` reads those vectors. So the vectors catch
a `tunnel-wire-rs` change only for as long as household-rs's encode/decode path
still routes through the neutral crate; a device-mesh slice that re-routes it
would silence the guard without editing it. If any change to `tunnel-wire-rs`
becomes necessary, the vectors are re-measured in a *separate, earlier* commit —
never regenerated in the same commit as the change.

### Phase 2 — dev-gated Soyeht datapath, `Machine-A` ⇄ `Machine-B`

Behind a `dev_*` feature, mirroring `dev_t1_datapath`: open a utun on
`Machine-A` and a tun on `Machine-B`, connect one TCP socket between the two
engines, pump IPv4 through a device-scoped `PacketPolicyPort`. No ceremony yet;
the peer identity is a dev fixture and every artefact says so.

**Exit:** DT1–DT5 green on dev hosts. The evidence pack states in its own text
that it is a **datapath** result with no authentication claim.

### Phase 3 — the keystone: a concrete session handle

Define one concrete `MeshSessionHandle` implementing `RevocableMeshSession`
(only two methods: `send_best_effort_revoke_notice`, `close`) plus an owner of
`Arc<MeshSessionHandle>` so `Weak<_>` handles become real. This unblocks
`RegistryD1Admission` and requires no protocol decision.

**Exit:** `RegistryD1Admission::new` is called from non-test code;
`MeshSessionRegistry::new` has at least one production call site; DT6–DT8 green.

### Phase 4 — a sealed entry point and a transport adapter

Promote a single sealed, roster-backed entry point taking a
`PrevalidatedIngress<TcpStream>` plus the already-real
`MachineRosterCoordinator` and `MeshSessionRegistry`, so
`run_responder_handshake` stops being unreachable **without** becoming callable
with a caller-chosen identity (DS1). Accept a TCP connection and hand it to
`admit_at_accept`.

**Entry gate:** the two blocked crypto decisions must be closed first — the
delegation-signing preimage layout, and a real `max_ttl` with the measurement
behind it (§12 Q2, Q3). Under the owner's delegation of micro-decisions these
are decided by the agents who own the crates, recorded as named decisions, and
reviewed; they are not escalated as questions.

**Exit:** a real `ActiveMeshSession` is produced from a real TCP connection
between two engines; DT9–DT12 green.

### Phase 5 — rendezvous and relay

Implement `Signal-S` against the R0b contract: CSPRNG ≥128-bit single-use
rendezvous id, 20 s TTL, minted server-side, distributed only over an
authenticated TLS channel, with the **fail-closed** refusal to emit an id over
any other transport.

**"Reuse the existing `Relay-R` splicer" — reconciled with the capacity plan,
2026-08-06.** An earlier revision of this phase said that in four words as if it
were free. `docs/soyeht-relay-vps-capacity-and-cost-plan.md` §3.1 and §4.3
measure the shipped configuration and reach a narrower answer, which this plan
adopts:

- **The splice *mechanism* is reusable and blind.** It moves opaque bytes; Noise
  terminates at the two endpoints, never at Relay-R (capacity §2.2). That is
  what DT15 is about and it is unaffected.
- **The shipped *public-mode configuration* is not viable for packets**, on
  three measured rows of capacity §3.1:
  `splice_max_bytes_per_direction = Some(72 MiB)` in public mode — *"kills a VPN
  in ~58 s at 10 Mbit/s"*; `splice_max_lifetime = 3600 s` — *"kills a VPN
  hourly"*; `splice_idle_timeout = 300 s` — *"structural no-op"*, because
  `mark_activity` timestamps every poll in either direction and VPN traffic is
  continuous, so the one knob the Share plan ranks cheapest does nothing here.
  Capacity §4.3 states the consequence directly: *"A VPN deployment needs a
  distinct configuration profile, not the Share profile with a larger number."*
- **A hard structural ceiling survives any profile.** Capacity R4:
  `MAX_SPLICE_IDLE_TIMEOUT = MAX_SPLICE_LIFETIME = 86,400 s`, so **no session
  can exceed 24 h**, and reconnection must be *designed*, not assumed — a new
  session means a new rendezvous, a new consumed-table entry, and a fresh Noise
  handshake.
- **The abuse caps must not be touched to make this work.** Capacity §3.2 and R3
  are explicit: `max_paired_splices_per_source = 128` and
  `max_pending_per_source = 16` bucket by source IP, which behind carrier CGNAT
  is *"a denial of service against legitimate users by construction"* for a
  consumer VPN — and the fix is an authenticated, principal-keyed admission
  token, a design change with a privacy cost, **not a raised constant**. This
  plan does not propose relaxing them, and DS-level review should reject any
  slice that does. Note the tension honestly: a principal-keyed admission token
  moves identity *toward* the relay, which trades against DS3/DT15's blindness
  claim. That trade is the capacity plan's §7 and is unresolved in both
  documents.

So Phase 5's dependency is not "reuse the splicer"; it is **"reuse the splicer
under a VPN configuration profile that does not exist yet"** (capacity §8), plus
a designed reconnection path. Neither is authored here — capacity checkpoint C3
must measure real per-session bytes before the VPN byte cap is set at all, and
this plan must not pick that number.

**Exit:** DT13–DT16 green, **plus DT25**. `Relay-R` holds no key and no
plaintext at any point in the exchange, demonstrated rather than asserted.

**Entry gate:** the VPN configuration profile (capacity §8) exists and is
recorded, or Phase 5's datapath rows are run against a dev profile and every
artefact says the shipped public profile would have terminated the session in
~58 s. A run under Share's profile that "passed" because it was short is not
evidence.

### Phase 6 — mode 2, user-operated overlay transport (`Overlay-U`)

Make the mode real, selectable, and testable, to per-claw §12's definition:
mode selection surface, mode recorded on every session and every audit event,
admission and revocation running over `Overlay-U`, and per-claw §12.3's
required product statement — *"the UI must say which of these properties are
provided by Soyeht and which by the user's own network"* — implemented for the
three that change hands here (DS3, DS9, byte-level audit under DS12), at the
point of revocation and at the point of mode selection.

**Entry gate: Q9 must be answered first.** Whether the mesh-session ceremony
runs over `Overlay-U` or reduces to admission only is undecided (§12 Q9), and
DT17 cannot be written until it is. Scoping this phase before that answer would
size two different amounts of work as one.

**Exit:** DT17–DT20 green, including the negative that proves DS6's limit is
*stated* rather than hidden.

### Phase 7 — `Phone-P`

Extend to the owner phone under the R0a owner-device profile. The mobile
datapath adapter question is the same one the mobile plan already scopes;
`claw-share-bridge-rs/src/lib.rs` (1,594 lines) already exposes
`VpnNetworkSettings { addr, prefix_len, peer, mtu, session_id }` and a
`ClawSession` whose reader/writer halves are split with the comment "so the read
and write loops the NEPacketTunnel runs do not contend" (`lib.rs:218`) — the FFI
was designed for a packet-tunnel consumer.

Note the standing constraint: **zero `.swift` and zero `.xcodeproj` files are
tracked in this repository**; the apps live elsewhere, so this phase spans two
repositories and its evidence must name both.

**Exit:** DT21–DT22 green on dev hardware.

### Phase 8 — adversarial re-review

Independent security re-review of DS0–DS13 against the code as built, with the
negative rows re-run by someone who did not write them.

---

## 7. The entitlement seam

The product will be charged for; the price and packaging are undecided and this
plan does not decide them. **`docs/soyeht-tiers-and-entitlement-plan.md` §5.0 is
normative for the entitlement chokepoint**, and this section cites it rather
than defining a second one — an earlier revision of this section named
`try_preauthorize_before` as *the* seam, which read as a second, independently
evaluated policy.

**Measured baseline: there is no billing, subscription, entitlement, or tier
code in this repository.** `git grep -i -c` over `admin/rust/` at
`origin/main` returns zero files for each of `stripe`, `billing`, `plan_id`,
`subscription_tier`, `entitlement_tier`. `ClawVpnAclKey { member_id,
device_pub, claw_id }` has no plan dimension, across all 60 lines in
`admin/rust/` that name that type.

### 7.1 The rule this plan adopts, unchanged

> **One `Entitlement` value type. One evaluation. N enforcement sites, each of
> which RECEIVES the value and never re-derives it.**

That is tiers §5.0's rule, quoted rather than paraphrased. Its chokepoint — the
*producer* — is `RelayStreamIssuerTrust::verify_offer_with_context`
(`server-rs/src/claw_share_relay_stream_issuer_trust.rs`), which carries the
fact as a field on `RelayStreamTrustContext`, beside `projection` and never
inside it.

**That producer does not serve this product, and saying otherwise would be
false.** `MeshSessionRegistry::try_preauthorize_before`
(`household-rs/src/mesh_session_registry.rs:1177`) takes
`(&SealedBinding, Weak<H>, Instant)`. It neither constructs nor receives a
`RelayStreamOfferContract`, so no arrangement of the relay-stream gate reaches
it. What is unified across the two products is the **policy object**, not the
call site: `try_preauthorize_before` is an **N-th enforcement site that receives
the value**, never a second place where it is computed. A second derivation is a
second policy, and two policies diverge — tiers records that as R-6.

Concretely, when this path is built:

- the `Entitlement` value is an **input** to admission, passed in by the caller
  that already holds it — not fetched, projected, or re-derived inside
  `try_preauthorize_before`;
- the same is true of the **transport mode** the session is admitted under
  (mode 1 vs `Overlay-U`), which tiers §8.4 requires to be an *admitted* fact
  rather than one inferred later from a socket, peer address, or interface name.
  Both are the same discipline applied to two different values, and both are
  cheap now and a redesign later (tiers R-10, O-7).

### 7.2 Three constraints the seam must satisfy

All derived from facts above rather than from pricing:

1. **The entitlement decision is an admission input, not a datapath input.** It
   is consumed where `try_preauthorize_before` already sits, so a lapse denies
   new sessions through the path that is already tested. Putting it in the pump
   would put a commercial decision inside `PacketPolicyPort`, which is the one
   seam `tunnel-wire-rs` exists to keep neutral.
2. **A lapse in `Overlay-U` mode stops Soyeht's session and not the
   connectivity** — the same asymmetry as DS6, and per-claw §12.3's S5 phrase:
   *authorization-complete but not necessarily reachability-complete*. A user who
   brings `Overlay-U` and stops paying loses Soyeht-mediated session
   authorization while their devices remain mutually reachable over their own
   network. Design for that answer now, or the first support incident is "I
   cancelled and it still works."
3. **A user who brings their own `Overlay-U` and pays nothing is a supported
   user.** Mode 2 must not be degraded to create pressure toward mode 1 — the
   same position tiers §2 records as the `Overlay-U` row of its tier table.

**Nothing is metered here.** The byte ceiling that covers `IpTunnel` and the
device wire is a single fixed constant owned by
`docs/soyeht-relay-vps-capacity-and-cost-plan.md` §6 L1 — identical for every
user, enforced at the endpoint, reported to nobody. This plan neither sizes it
nor gates it on entitlement.

Everything else — free-tier shape, trial length, what Share includes at each
tier — is deliberately absent from this document.

---

## 8. Test matrix

PASS is stated per row. A row is green only in the phase that owns it, and only
with its negatives.

| ID | phase | proves | PASS condition |
|---|---|---|---|
| DT1 | 2 | interface up | `Machine-A` opens a utun and `Machine-B` a tun with the assigned device-mesh addresses; clean exit removes both |
| DT2 | 2 | forwarding | ≥60 s of traffic with ≥98% ICMP delivery (or an exact `N/N` count) **plus** a TCP echo, `Machine-A` ⇄ `Machine-B`, over the Soyeht socket. Pump counters may corroborate; they never substitute for end-to-end delivery evidence |
| DT3 | 2 | route scope | each host's route table contains only the peer's device-mesh address via the tunnel; no default route, no LAN route, no `Overlay-U` route, no claw route through the tunnel |
| DT4 | 2 | teardown | kill the socket mid-session → interface gone, routes gone, no half-open state, no orphan process |
| DT5 | 2 | evidence honesty | the Phase-2 artefact states in its own text that peer identity is a dev fixture and the run carries no authentication claim; a reviewer who reads only the artefact cannot conclude otherwise |
| DT6 | 3 | handle exists | `RegistryD1Admission::new` is constructed from non-`#[cfg(test)]` code with a real `Weak<MeshSessionHandle>` |
| DT7 | 3 | revocation reaches the handle | revoking a registered session causes exactly one `send_best_effort_revoke_notice` and one `close` on the concrete handle, with the registry lock **not** held during either |
| DT8 | 3 | checkpoint-driven revocation | a new checkpoint carrying a tombstone, a drop-from-active-set, or a changed cert fingerprint revokes the live session; a fork or regression drives the registry to `Unavailable` |
| DT9 | 4 | ceremony over a real socket | `Machine-A` and `Machine-B` complete Idle→…→Active over one TCP connection and exchange `0x10` DATA frames |
| DT10 | 4 | admission is roster-backed (DS1 negative) | a peer whose identity is self-consistent but absent from the roster is rejected; no `ActiveMeshSession` is produced; the reject is generic (no value echo) |
| DT11 | 4 | replay negatives | replayed intent, replayed auth frame, and a nonce at the **window boundary** are all rejected, with zero route or session side effects |
| DT12 | 4 | expiry is the minimum | a session whose intent `not_after` is earliest expires at that instant, not at the checkpoint's or the lease's |
| DT13 | 5 | rendezvous fail-closed | `Signal-S` refuses to emit a rendezvous id or candidates over any transport that is not the mandated authenticated-TLS channel — no plaintext fallback, no downgrade — verified by attempting it |
| DT14 | 5 | id hygiene | the id is CSPRNG, ≥128 bits, single-use, expires at 20 s, and does not derive from household id, target identity, or any mesh public key |
| DT15 | 5 | relay is blind | over a full mode-1 session through `Relay-R`, the relay holds no key and no plaintext; a captured relay-side view yields nothing decryptable |
| DT16 | 5 | relay compromise ≠ access | a hostile relay that replays or reorders what it has seen obtains no session; it can DoS ids it has already seen (accepted, inherent) |
| DT25 | 5 | the session survives the profile it will actually run under | a mode-1 session sustains continuous traffic past **both** shipped public-mode bounds that capacity §4.3 measures as fatal — ≥ 72 MiB in one direction and ≥ 3,600 s of wall clock — under the VPN profile, with the termination reason and `/status` counters recorded. Running the same test under Share's profile and passing because the run was short is an **invalid** result, and the artefact must state which profile it ran under |
| DT17 | 6 | mode 2 works | **Not yet writable — blocked on Q9.** `Machine-A` and `Machine-B` complete admission and exchange traffic over `Overlay-U` with no Soyeht tunnel interface created and no Soyeht route installed. What "exchange traffic" must assert depends on whether the mesh-session ceremony runs over the overlay (assert a `0x10` DATA frame) or reduces to admission only (assert **no** `ActiveMeshSession` is created). Writing this row as-is, without deciding, is how the ambiguity would ship |
| DT18 | 6 | mode 2 revocation is de-authorization (DS6) | revoking in mode 2 stops Soyeht-mediated forwarding and session authorization **and** the test asserts the peer is still IP-reachable over `Overlay-U` — the honest result, recorded as such, not treated as a failure |
| DT19 | 6 | DS3, DS6 and DS9 are stated, not hidden | the mode-2 revocation UI/audit output names the DS6 limitation, **and** the mode-selection surface names all three properties that change hands (DS3 confidentiality, DS9 no-forwarding, byte-level audit under DS12) — per-claw §12.3's required product statement. A reviewer reading only the product output cannot infer parity with mode 1 on any of them |
| DT20 | 6 | no silent fallback (DS7) | with `Overlay-U` available, a mode-1 session that cannot establish fails closed with a redacted error and never completes over `Overlay-U`; with mode 2 selected, no Soyeht tunnel is ever opened |
| DT21 | 7 | phone joins | `Phone-P` reaches `Machine-A` and `Machine-B` under the owner-device profile; only the device-mesh routes are installed; no default route |
| DT22 | 7 | phone lifecycle | background/foreground, screen lock, Wi-Fi⇄cellular flap, app kill: reconnect or fail closed — never a stale route, never a stale "connected" state |
| DT23 | all | separation from claw VPN (DS10) | a device-mesh grant presented at the claw admission point is rejected generically, and a claw grant presented at device-mesh admission is rejected generically; neither produces a session or a route |
| DT24 | all | audit hygiene (DS12) | every event carries reason codes, neutral ids, and the transport mode; no payloads, no real addresses, no `session_id` through a formatter |

Rows are ordered by owning phase, not by number — DT25 was added later and sits
with the other phase-5 rows rather than at the end.

Platform variants: DT1–DT16, DT23–DT24 and DT25 run against both a macOS host
and a Linux host as `Machine-A`/`Machine-B`.

---

## 9. Relation to the per-claw plan

**Which document governs what.** The full five-document index is at the top of
this file; the two rows that matter here are: **per-claw §12** is canonical for
user-operated overlay transport (`Overlay-U`) and its per-mode security table
(§2 adopts it), and **tiers §5.0** is canonical for the entitlement chokepoint
(§7 adopts it). This document is canonical for device⇄device: the mesh-session
ceremony, the device wire, DS0–DS13, and the direct-path resolution the capacity
plan assigns here (§3.4.1) — while the **capacity plan** is canonical for the
relay limits any Phase-5 session actually runs under (§6's entry gate, DT25).
Neither document re-states the other's material; a disagreement is a defect in
whichever one is not canonical for that subject.

### 9.1 Shared

| shared | where |
|---|---|
| the definition of user-operated overlay transport, and its per-mode security table | **per-claw §12** — canonical; this plan adopts it (§2) |
| household identity chains | `machine_cert.rs`, `member_identity.rs` |
| signed roster, checkpoint chain, revocation currency | `machine_roster_store.rs`, `machine_roster_authority.rs` |
| owner-PoP authorization | `household_auth::authorize_request` |
| the blind relay | `Relay-R` (`relay_stream_relay_dev` bin + the rendezvous stream listener) |
| neutral wire mechanics | `tunnel-wire-rs`: `PollablePump`, `PacketPolicyPort`, `frame_stream`, `worker_pool`, `TunnelFrame` |
| TUN/utun open primitives | `claw_vpn_macos_utun.rs`, `claw_vpn_linux_tun.rs` |
| the discipline that flags default off and each activation is its own owner event | both plans |

### 9.2 Separate

| separate | device mesh | per-claw |
|---|---|---|
| authorization record | its own keyed relation (DS10) | `ClawVpnAclKey { member_id, device_pub, claw_id }` |
| session establishment | mesh-session ceremony (Noise-XX + `0x06` intent + `0x01`–`0x05` frames) | relay_stream offer verify → dial → `SessionAuthToken` PoP → `IpTunnel` |
| wire constants | device-scoped probe value, device ack, device settings mirror, device error enum (§3.2) | `claw-share/health/v1`, `TunnelAck`, `0x17` mirrors, four authorization error variants |
| address pool | its own prefix (§3.5, Q1) | the claw pool |
| what a session connects | two devices | one device and one claw |
| current client status | none — this plan builds it | `friend-cli-rs/src/main.rs:1054` still `bail!("relay_stream IpTunnel payload is not implemented in this client")` |

### 9.3 The non-goal that has been amended — and the obligation it hands back

The per-claw plan's original non-goal read:

> NOT a mesh: no claw⇄claw or device⇄device routing; **no nvpn/mesh promises
> until daemon + interface + routes are proven** per this plan.

That sentence was true for the per-claw product and **remains true for it**. Its
author has since amended it in place — per-claw §7, second bullet — scoping it
rather than deleting it, so the record shows a second product was added rather
than an invariant quietly dropped. (Cited by section, not by line: that document
is under concurrent edit, per R10. An earlier revision of this plan cited a line
number in it and the line had already moved.)

**The amendment assigns this document a specific obligation, and it is answered
here rather than acknowledged.** Per-claw §7 requires: *"the mesh plan must
state, explicitly, which mechanism replaces S9 once the two-address invariant no
longer applies — it does not inherit S9 by being adjacent to this document."*

The answer, in three parts:

1. **The two-address invariant is not abandoned; it is re-scoped from
   `(device, claw)` to `(device, device)`.** DS9 states it in this document's
   own vocabulary: *"The device-mesh packet policy accepts only the session's
   own address pair in both directions."* Same mechanism class — a
   `PacketPolicyPort` check per session — over a different pair. A device⇄device
   mesh of exactly two machines and one phone (DS13, R0a D4) is still
   point-to-point per session; there is no forwarding table here either, because
   there is no forwarding.
2. **What changes is cardinality, and that is where the replacement mechanism
   must be argued, not assumed.** With three principals there are three possible
   pairs, so "the session's own address pair" is no longer synonymous with "the
   only pair that exists". DS9's enforcement is therefore per-session and must be
   proven per-session; **DT3 (route scope) and DT23 (claw/device separation) are
   this plan's version of S9's bar**, and DT3 explicitly requires that no LAN,
   `Overlay-U`, or claw route pass through the device tunnel. If R0a is ever
   amended to allow N machines (DS13), DS9's argument does **not** extend for
   free — that amendment must re-derive it, because at N > 3 the temptation to
   add a forwarding path is what the original sentence was guarding against.
3. **In mode 2, DS9 is lost, exactly as per-claw §12.3 records S9 as `NO`.** No
   Soyeht policy port is in the path. This is stated in §2.1 and DS8 rather than
   left to be discovered.

The clause about proving daemon, interface and routes before promising a mesh is
not weakened, and per-claw §7's non-transferability note is accepted without
qualification: **§0.6's owner-present observation there is not evidence here**,
and neither is any M1 run (DS0). §8's DT1–DT4 are this plan's version of that
bar, and they are unrun.

---

## 10. Non-goals (v1)

- **Not a full-tunnel VPN.** No default route, no exit node, no LAN exposure,
  no split-DNS.
- **Not direct-path traversal *in v1* — deferred with a firing trigger, not
  declined.** v1 mode 1 is relay-first (§3.4). The reasoning the capacity plan's
  §6 L0 assigns to this document, and the trigger at which the deferral expires
  (~48 mode-1 users' worth of egress, or Phase 5 exit, whichever is first), are
  recorded in §3.4.1. This entry is listed under non-goals for scope, **not** as
  a settled "no": capacity checkpoint C10 says silence is not a decision, and
  re-deferring past the trigger requires a written decision, not this bullet.
- **Not N devices.** Two machines and one owner phone, per R0a D4 (DS13).
- **Not claw routing.** A device-mesh session never reaches a claw; that is the
  per-claw product's job and its own authorization (DS10).
- **Not a datagram/QUIC relay mode.**
- **Not pricing.** The entitlement seam is designed (§7); the packaging is not.
- **Not an operator of the user's `Overlay-U`.** Per-claw **§12.4** is canonical
  and applies here verbatim — we do not install, configure, operate, recommend a
  specific vendor for, hold credentials for, troubleshoot, proxy through, or
  read the ACL of the user's overlay, and we make no availability claim about
  it. Adopted by reference rather than restated, so the two documents cannot
  drift into two different non-goal lists (R10).

---

## 11. Risks

- **R1 — "26,694 lines never compile" is quoted into a decision, in any of its
  three wrong forms.** The **size** is wrong first: the measured figure is
  **26,692** tracked `.rs` lines across 28 files, by the predicate in §1.3, and
  a number quoted without its predicate is how `26,694` survived this long. The
  original claim is then false for the library half
  (§1.3) — quoting it justifies either deleting coverage or funding delivered
  work. **The first correction of it over-corrected**, and this plan carried the
  over-correction: "the sources compile, only the tests don't" is also wrong,
  because `tests/model_invariants.rs` — 6,137 lines, 134 of the 345 tests — does
  not compile either, behind a three-feature `cfg` no single-feature invocation
  can satisfy (§1.3.2). The precise sentence is at the end of §1.3.2 and is the
  only one that should be quoted. The general shape of this risk is worth
  naming: **a correction is quoted as confidently as the claim it corrected, and
  gets audited less.**
- **R2 — Un-excluding the crates looks like tidying.** Two security properties
  depend on the current shape (§5.3). Any change to `exclude` must name both.
- **R3 — The graph gate reads green while measuring nothing.** This is the
  instrument enforcing the Product A / feature-off boundary, and its own CI
  comment records two separate failures of exactly this kind: it existed with a
  baseline, an allowlist and two non-vacuity probes while **no job invoked it in
  any spelling**, and it "has failed since 6d1ce46c and nobody saw it for 63
  commits, including the approval that declared 'gates green'"
  (`backend-ci.yml:345–352`); separately, its exit line was
  `[ "$fail" -eq 0 ] || exit 1`, so `pass=0 fail=0 skip=7` exited 0. Both are
  fixed, and CI now runs `structural` and asserts `skip=0` at the call site.
  Adding a crate or a feature changes its baseline; whoever adds one re-pins
  `admin/rust/scripts/graph-gate/baseline-cf3969fd.json` and
  `allowlist-mesh-session-runtime.txt`, or the next boundary violation lands
  behind a green tick.
- **R4 — A fail-closed default is relaxed as "configuration." (widened
  2026-08-06; an earlier revision of this plan narrowed it on a wrong
  measurement.)** `max_ttl: 0` and `NoVerifierConfigured` are the current
  fail-closed floor, and making the ceremony reachable end to end requires
  changing both. This plan previously claimed the most obvious version of the
  mistake — reaching for the injectable constructor — was already closed by the
  compiler. **It is not**, at the seam that matters: the seam's type is
  `mesh-session-control-model-rs/src/validator.rs:124`, whose `test(max_ttl)`
  has no `cfg` and whose `max_ttl` field is `pub`, so both the constructor and a
  bare struct literal are available to non-test code (full measurement and
  commands in §1.8 item 3). The `#[cfg(test)]` gate exists only on the
  *other*, same-named type at
  `mesh-session-core-rs/src/delegation.rs:369`, which this seam does not use.

  So the risk has three faces, not one: (a) a `configured()` constructor landing
  with an unmeasured number (DS11, Q2); (b) a caller calling `test()` or writing
  the struct literal in production code, which compiles today; (c) a reviewer
  reading `production()`'s doc comment and concluding the floor is enforced. The
  mitigation for (b) and (c) is Q7 — a source-level guard or a visibility change
  in the owning crate — and until one lands, DS11 is a **review obligation**,
  not a compiler guarantee, and any slice touching the delegation path must be
  reviewed on that basis.
- **R5 — `run_responder_handshake` goes `pub` "just to test end to end."** That
  *is* the bypass (DS1). Any slice proposing it must land the sealed
  roster-backed authority in the same change.
- **R6 — Changing `tunnel-wire-rs` moves shipped bytes, and its guard is in
  another crate.** `tunnel-wire-rs` is shared with the Share/relay_stream
  datapath and per-claw VPN. Behaviour identity is held by frozen vectors that
  deliberately landed in an **earlier** commit so they could not have been
  regenerated by the move — but the vectors live under `household-rs/tests/data/`
  and are read only by an inline household-rs test (Phase 1 exit). A device-mesh
  slice can therefore weaken that coverage by re-routing household-rs's
  encode/decode path, with no edit to the vectors or the test. Any generalisation
  must be measured against them, and they must not be regenerated in the same
  commit as the change.
- **R7 — M1 evidence is read as product evidence.** It says PASS, it says
  "mesh", it runs two real engines — and it proves Tailscale connectivity plus
  owner-PoP authorization. DS0 forecloses it; reviewers should still expect to
  see it offered.
- **R8 — Relay cost scales with users, and the trigger fires early.**
  Relay-first (§3.4) means mode 1 traffic crosses `Relay-R`. The rented host
  must be sized on measured per-session bandwidth (capacity C3), and the
  direct-path slice is the mitigation, not an optimisation (§3.4.1, Q4).
  Quantified from the capacity plan rather than asserted: the S4 trigger — 50%
  of one node's 1 TB allowance — is crossed by a VPN workload at **~48 users**,
  and the lever is worth roughly 3× at 100,000. The specific failure mode is
  **silent re-deferral**: a non-goal bullet reads like a decision, so nobody
  re-opens it. §3.4.1's expiry condition exists to make that impossible; if a
  future revision deletes the trigger and keeps the bullet, this risk has
  materialised.

- **R11 — Phase 5 "reuses the splicer" under a profile that would kill it.**
  The splice mechanism is reusable and blind; the shipped public-mode
  *configuration* terminates a VPN session in ~58 s (72 MiB cap) or hourly
  (3,600 s lifetime), and 24 h is a hard structural ceiling regardless of
  profile (capacity §3.1, §4.3, R4). The concrete hazard is an evidence one: a
  Phase-5 run short enough to finish under Share's profile passes DT13–DT16 and
  proves nothing about a VPN session. DT25 and Phase 5's entry gate exist for
  that. The second hazard is the tempting fix — raising
  `max_paired_splices_per_source` or `max_pending_per_source` to relieve the
  CGNAT bucket collision. Those are **abuse controls**; capacity §3.2 and R3 say
  so at the call site, and the real fix (a principal-keyed admission token)
  trades against `Relay-R`'s blindness. Naming it as a risk rather than
  proposing the relaxation.
- **R9 — Mode 2's limits are read as parity.** DS3 and DS6 are limits of the
  mode, not bugs. DT18/DT19 exist to force them into the product output.
- **R10 — This track is one of five documents landing together, and the
  cross-references are live.** The per-claw and mobile rewrites, the capacity
  plan and the tiers plan are authored by other agents, concurrently. Each
  cross-reference here names a **document and a section**, never a line number:
  an earlier revision of this plan cited `product-a-per-claw-vpn-plan.md:637`
  and that line had already moved by the time it was reviewed (§9.3). The
  sharper form of this risk is **divergent definition, and it materialised**:
  **four** of the five documents defined the user-supplied-transport mode
  independently — four names for one owner decision, and three independent
  resolutions of one contradiction — which is how one decision becomes four
  products. §2 resolves it by naming per-claw §12 canonical and adopting it, and
  the 2026-08-06 convergence pass retired the other three names. **The mechanism
  that prevents a fifth** is the "which document is normative for what" block at
  the top of each of the five files; §9's note is the same statement from this
  document's side. The residual risk is that a later edit to §12 does not
  propagate here — which the index makes visible rather than eliminates.

---

## 12. Open questions, each with the measurement that settles it

**Q1 — Which address prefix does the device mesh use?**
*Settled by:* an enumeration of every prefix already claimed in this repository
— `classify_local_address`'s Tailscale ranges, `InterfaceClass::Mesh`'s
configured range, and the per-claw pool — plus a decision recorded in this
document. Until then §3.5 states the constraints, not the answer.

**Q2 — What is a real `max_ttl` for a mesh-session delegation?**
*Settled by:* an operational measurement of reauthorisation cost against the
window a compromised delegated key stays useful. `signer_seam.rs` states
explicitly that inventing a constant here is the failure mode. Under the owner's
delegation of micro-decisions this is decided by the crate owners and recorded
as a named decision with its measurement — not escalated.

**Q3 — What is the delegation-signing preimage byte layout?**
*Settled by:* mesh-core publishing it. `SignatureVerifier`'s own doc says the
control model "does not get a vote on that byte layout". This is a design
decision blocking code, and it is Phase 4's entry gate.

**Q4 — Is the pump's second fd generalisable from a relay socket to a direct
peer socket?**
*Settled by:* reading `pollable_pump.rs`'s fd handling and attempting the
substitution in a scratch tree. The pump takes two `RawFd`s and knows nothing
about what is behind them, which suggests it is a one-line change — but that is
an inference from the module doc, **not a measurement**, and this document does
not claim it.
*Why it is now on the critical path:* §3.4.1 puts a firing trigger on the
direct-path deferral, so this measurement stops being idle curiosity at the
moment that trigger fires. Take it before then; it is a scratch-tree
experiment, not a slice.

**Q5 — What does production pass as `cell::open`'s `spy: Arc<OrderSpy>`?**
*Settled by:* either a documented production value or a `cell::open`-adjacent
constructor that does not take one. `signer_seam.rs` names this as blocker (b)
and warns that closing the visibility wall alone would paper over it.

**Q6 — Does `Phone-P` need a distinct wire, or does the machine wire serve it?**
*Settled by:* comparing the owner-device profile's admission inputs against the
machine profile's in R0a §2, and checking whether
`SealedBinding::from_membership_key` accepts both. Not investigated in this
document.

**Q7 — Should the delegation TTL floor be compiler-enforced, and by whom?**
Measured today: it is not (§1.8 item 3, R4). The seam's type
(`mesh-session-control-model-rs/src/validator.rs:124`) has a `pub max_ttl` field
and an ungated `pub fn test(max_ttl)`. Its same-named neighbour
(`mesh-session-core-rs/src/delegation.rs:369`) has a private field and a
`#[cfg(test)]`-gated constructor — so the enforced shape already exists in this
repository, one crate away, and the question is whether the control-model type
should adopt it.
*Settled by:* the owners of `mesh-session-control-model-rs` deciding, and a RED
that proves it either way. The RED shape is specific: a compile-fail case
asserting that `DelegationPolicy { max_ttl: 1 }` and `DelegationPolicy::test(1)`
are **not** constructible from a non-test build of a dependent crate. A positive
test cannot catch this — it would be `Ok` under either shape. Until that RED
exists, DS11 is a review obligation, not a guarantee, and this plan says so
rather than assuming the gate.
*Not this plan's to change:* widening or narrowing another crate's visibility is
that crate's decision. Filed, not done.

**Q8 — Is enabling `test-support` + `roster-sync-unratified` in a CI `cargo
test` step compatible with the manifest's own prohibition?**
`keystore-rs/Cargo.toml:13–15` says those features *"stay OFF: the gated D4
surface (fault injection, `seed_for_test`, RosterSync) must not exist in any
keystore build."* §5.1 O1 turns them on. The two are reconcilable only if "any
keystore build" is read as "any build whose artefact is consumed" rather than
"any `cargo` invocation" — a reading the manifest does not state.
*Settled by:* the `keystore-rs` owners either narrowing that sentence in the
manifest, or O1 being replaced by an invocation that does not enable them (which
on today's `cfg` is impossible — the conjunction at
`keystore-rs/src/lib.rs:110–116` requires all three). **This is a real
tension, not a formality: if the answer is "the prohibition is absolute", then
`model_invariants.rs` can only ever be executed from the standalone crate, and
O1 must be replaced by an O4-shaped invocation there.** That alternative is
cheap to test and has not been measured: `( cd
admin/rust/mesh-session-control-model-rs && cargo test --features
test-support,roster-sync-unratified )` — which runs the *standalone* instance,
not the co-located one `keystore-rs` compiles, and therefore proves a different
thing. Which of the two instances the 134 tests must run against is itself part
of this question.
*Second, unmeasured half:* each excluded crate has its own `Cargo.lock`, so O4's
`--locked` behaviour and CI cache reuse differ from the workspace steps. Not
measured; measure before assuming the step is cheap.

**Q9 — In mode 2, does the mesh-session ceremony run *over* `Overlay-U`, or does
mode 2 reduce it to admission only?**
This document does not know, and two of its own statements depend on the answer:
§2.2's "session key agreement" row (marked undecided) and DS3's mode-2 clause
(which is written as if the answer is "admission only", and is too strong if it
is not). DT17 is ambiguous on the point — *"complete admission and exchange
Soyeht traffic over `Overlay-U`"* does not say whether that traffic is
Noise-wrapped.
*Why per-claw §12 does not settle it:* there the analogous answer is
unambiguous — *"there is no `IpTunnel` session … Our code is not in the path at
all"* — because a claw session **is** the datapath. A device⇄device session is
not: admission and key agreement are separable from carriage, so the question
that has no content for per-claw has content here. This is the one place
adopting §12 wholesale would import an answer to a question §12 was not asked.
*Settled by:* a decision, then DT17 rewritten to assert it. If the ceremony
runs, DT17 must assert a `0x10` DATA frame observed on the overlay path and DS3
loses its mode-2 clause; if it does not, DT17 must assert that **no**
`ActiveMeshSession` is created in mode 2 and that the authorization record is
produced by a different path — which is then a surface this plan has not
designed. Decide before Phase 6 is scoped; the two answers are different amounts
of work, and DT17 cannot be written until one is chosen.

---

## 13. Owner and infrastructure unlocks

Everything not listed under "requires owner action" proceeds as implementation
and review work, without ceremony. T1-class dev-host decisions on this track are
delegated to the agents per the owner's 2026-08-06 instruction; the plan states
what will be done and by whom rather than asking.

**Proceeds automatically:** documentation; the Phase-0 CI additions; the
device-mesh wire module; the dev-gated Phase-2 datapath on dev hosts; the
concrete session handle; the sealed entry point; unit, mocked, and dry-run
tests; redacted evidence formatting; review-response edits that do not grant
real access, mutate a shared host, publish private evidence, or activate
production.

**Requires the owner or infra:**

- Confirm the `Relay-R` endpoint as a private operator value when Phase 5 starts
  (public docs use the alias only).
- Confirm a Linux dev host is available as `Machine-B` when Phase 2 starts, and
  that it carries **no pre-existing household identity** before any pairing
  ceremony — verified, not assumed.
- Approve real enrollment and real device-mesh grants between real devices.
- Grant owner-present, scoped elevation when a run needs TUN/utun or route
  mutation on a dev host.
- Amend R0a if the product needs a third machine or a second phone (DS13).
- Approve publication of any evidence outside the private store.
- Authorize production activation, each deploy touching a shared host, and each
  flag flip — individually. A relayed authorization is not authorization.

Agents must not request passwords in chat and must not print secrets. Raw
captures live as mode `0600` files inside mode `0700` ignored directories;
public summaries carry aliases only.

---

## 14. Definition of done

The device⇄device mesh VPN is complete when:

- the 345 previously-unexecuted tests execute in CI, delivered as Phase 0's four
  counted criteria rather than as one aggregate claim: O1 = 134, O4 = 211,
  each with its count recorded; O3's 29 runtime tests and its trybuild proof
  execute; O2 keeps `skip=0` and compiles both excluded crates as separate
  roots. O1/O3/O4 run on both runners; O2's runner placement is recorded as a
  decision (Phase 0). WI-0a — the three-feature trap at
  `keystore-rs/src/lib.rs:110–116` — is closed by a step **outside** the
  feature-surface loop plus a comment inside it explaining why a
  conjunction-gated target can never appear there;
- `Machine-A` and `Machine-B` exchange IP over a Soyeht-owned datapath with a
  real, roster-backed, revocable session (DT1–DT12);
- rendezvous is fail-closed and `Relay-R` is demonstrably blind (DT13–DT16),
  **and** a session survives past the shipped public-mode byte cap and lifetime
  under a recorded VPN configuration profile (DT25, capacity §8);
- the direct-path decision is recorded against capacity checkpoint C10 — either
  the slice is scheduled, or a written decision states why an egress-bound
  workload keeps always-relay (§3.4.1);
- mode 2 is a selectable mode, defined as per-claw §12 defines it, whose DS3,
  DS6 and DS9 limits appear in the product's own output (DT17–DT20), with Q9
  answered before DT17 was written;
- `Phone-P` participates under the owner-device profile with per-peer route
  scope and clean lifecycle behaviour (DT21–DT22);
- device-mesh and per-claw authorizations are provably separate (DT23);
- audit output carries reason codes, neutral ids and the transport mode, and
  nothing else (DT24);
- an independent re-review of DS0–DS13 against the code as built is clean;
- the entitlement seam exists at the admission point with DS6's asymmetry
  designed for, and no pricing decision is embedded in the datapath;
- rollback is documented and exercised, and production activation remains a
  separate, explicitly owner-authorized event.
