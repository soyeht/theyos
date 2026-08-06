# Relay-R — Capacity and Cost Plan (Share + VPN)

Status: **DRAFT** — no decision in this document is activated. It states what the
relay layer costs, what it can and cannot see, and what must be re-measured
before a public launch. Production activation, deploy, and flag flips remain
separate owner-authorized events.

**Tree under measurement.** Every code fact, line number, and default in this
document was read from `origin/main` at commit
`e60bad85313eb39c9a000a29852bde1a944e425e` ("Merge pull request #422", dated
2026-08-06). Nothing here was measured against a working tree. Line numbers are
valid **only** for that commit; re-anchor before citing them elsewhere.

<!-- doc-freshness-anchor
measured: 2026-08-06
sha: e60bad85313eb39c9a000a29852bde1a944e425e
paths:
  - admin/rust/server-rs/src/claw_share_relay_stream_*
  - admin/rust/server-rs/src/claw_share_rendezvous_stream_relay*.rs
  - admin/rust/server-rs/src/claw_share_relay_loop.rs
  - admin/rust/server-rs/src/bin/relay_stream_public_relay.rs
  - admin/rust/server-rs/examples/relay_stream_s0_load.rs
  - admin/rust/server-rs/Cargo.toml
  - admin/rust/household-rs/src/claw_share*.rs
  - admin/rust/claw-share-bridge-rs/src/lib.rs
  - admin/rust/nostr-relay-rs/
  - admin/rust/core-rs/src/network_detect.rs
-->

The hosting facts in this document have no anchor and cannot get one: the gate
measures git history, and a provider console is not in git. Treat every
*account console* figure as expiring on its own read date.

**Two sources, kept apart.** This document mixes code facts with **hosting facts
read from the provider's account console on 2026-08-06**. They are never blended:
code facts carry a file and a line, console facts are labelled
*account console, read 2026-08-06*, and figures that are neither — the vendor's
**published plan spec** — are labelled as such and are the weakest thing here. A
plan-spec number must never be quoted as a measurement. Where the two disagree
about the same quantity, the console wins and the disagreement is recorded rather
than reconciled.

**Aliases.** The rendezvous/splice VPS is **Relay-R**. The Nostr gossip relay
the engine publishes household-log entries to is **Relay-N**. The overlay
network a user brings and operates themselves is **`Overlay-U`**, and the mode
is **user-operated overlay transport** (per-claw §12, which also holds the
single registry of the spellings this mode retired — including the one this
document used; that list is not restated here). No hostnames, IP literals,
provider names, account identifiers, regions, or deployment paths appear in this
document; the repository is public. Where the cost model needs a price it uses
an **instance class**, which carries the same arithmetic as the real instance
without the locating detail.

### Which document is normative for what

Settled 2026-08-06 across the five Product A / cost plans, so that a shared
concept is resolved **once**. A document that is not normative for a row cites
that row's owner and does not restate it; where two documents disagree, the
defect is in the non-normative one.

| shared concept | normative document |
|---|---|
| transport modes — the Soyeht datapath vs **user-operated overlay transport** (`Overlay-U`) | `docs/product-a-per-claw-vpn-plan.md` **§12** (per-mode security table: §12.3) |
| entitlement chokepoint | `docs/soyeht-tiers-and-entitlement-plan.md` **§5.0** |
| relay cost, capacity, and the limits a session runs under | **this document** |
| device⇄device track | `docs/product-a-device-mesh-vpn-plan.md` |
| iOS client state | `docs/product-a-mobile-claw-control-vpn-plan.md` |

### The instance class, and where each figure comes from

Relay-R is **one already-rented VPS**: the provider's smallest shared-CPU
instance. The figures below are separated by provenance, because they are not
equally reliable and must not be laundered into one another.

| figure | value | provenance |
|---|---|---|
| vCPU | **1** | **account console, read 2026-08-06** |
| RAM | **~961 MB** | **account console, read 2026-08-06** |
| disk | **25 GB** | **account console, read 2026-08-06** |
| instance price | **~US$5.00/month** | **account console, read 2026-08-06** |
| observed load average | **0.06** — essentially idle | **account console, read 2026-08-06** |
| observed memory in use | **339 MB of 961 MB** (~622 MB free) | **account console, read 2026-08-06** |
| monthly transfer meter | **0.11% used**, on an account **two days old** | **account console, read 2026-08-06** |
| included transfer | **~1 TB/month** | **PUBLISHED PLAN SPEC — not account-read.** The absolute allowance was not visible on the console pages that were read |
| transfer overage | **~US$0.005/GB** | **PUBLISHED PLAN SPEC — not account-read.** Same caveat |

Two consequences of that split, stated before any arithmetic uses the numbers:

1. **The two figures the whole cost model rests on — the allowance and the
   overage rate — are the two that were *not* measured.** They are the vendor's
   published plan spec. Everything in §4.6 and §4.7 is conditional on them. The
   measurement that settles it is a billing-page read at the end of a month with
   non-trivial usage, not a plan page (§11 Q6).
2. **The transfer meter carries no live signal.** 0.11% on a two-day-old account
   is indistinguishable from zero. It tells us the relay is not currently near
   any limit; it tells us nothing about a VPN workload, and it must not be
   extrapolated. It also does not establish whether the meter is per-instance or
   pooled across the account, nor whether it counts ingress — which is exactly
   why Q6 stays open rather than being closed by this reading.

**RAM is 961 MB, not 1 GiB.** Every memory percentage in this document is taken
against 961 MB, and against the **~622 MB actually free** where that is the
honest denominator.

---

## 1. What this plan decides, and what it defers

| decides | defers |
|---|---|
| What Relay-R can and cannot observe, stated from code rather than from intent | Price, packaging, and tier boundaries (owner-deferred; see the tiers plan) |
| Which shipped defaults are wrong for packet traffic, and what a VPN profile sets them to | Production activation of any profile |
| The per-session resource cost and the two ceilings it produces | Whether direct-path is *enabled* for stranger-facing Share (it is not) |
| The cost formula, written so it re-derives when the inputs change — and it has now been re-derived once, against real account figures, without any ratio moving (§4.6) | Whether to keep this instance class, add instances, or co-locate the VPN profile on the existing one (§8 placement; needs C4) |
| Which constraint binds **first**, kept separate from which costs **most** (§6.0) | The entitlement mechanism itself — the tiers plan owns it; this document specifies **no meter** (§6 L1) |
| Which of the four owner requirements are in tension, and where the trade is taken | Whether the metadata Relay-R sees is *retained* beyond process memory |

**One-line summary of the finding.** For Share, concurrency binds and egress is
free. For VPN, that inverts: **egress binds and concurrency is nearly free.**
Every lever the Share plan ranks highest (buffer sizing, `splice(2)`, io_uring)
moves the term that stops mattering, and the lever it defers behind a trigger
(direct-first) becomes the only one that changes the order of magnitude.

**And a second finding that qualifies the first, added after the account read.**
Egress dominates the *infrastructure bill*, but the infrastructure bill does not
dominate anything: at ~US$0.005/GB a user moving 10 GB/month costs about
**5 US cents/month**, and 20 GB costs about **10 cents**. **Transfer is not what
makes this product expensive.** Both sentences are true at once and they are not
in conflict — being egress-bound means egress is the term that *grows* the node
count, not that the total is large. The practical consequence is that a per-user
byte budget is an **abuse backstop**, not a pricing mechanism (§6 L1), and that
the constraints must be ranked by *what fails first*, not by *what costs most*
(§6.0).

---

## 2. What Relay-R sees — measured, not asserted

### 2.1 The one thing it parses

Relay-R parses **exactly one structure** on the wire: a 4-byte header plus a
token.

`read_bounded_hello` reads 4 bytes, takes `token_len` from `header[2..4]` as a
big-endian `u16`, rejects anything above `MAX_RENDEZVOUS_TOKEN_LEN = 128`, reads
`token_len` more bytes, and decodes a `RendezvousHello { version: u8, role:
Guest|Claw, token }` with the token bounded to `16..=128` bytes.

- `admin/rust/server-rs/src/claw_share_rendezvous_stream_relay_listener.rs`
  `fn read_bounded_hello`, L586–614
- `admin/rust/household-rs/src/claw_share_rendezvous_token.rs` L17–18
  (`MIN_RENDEZVOUS_TOKEN_LEN = 16`, `MAX_RENDEZVOUS_TOKEN_LEN = 128`)

After the hello, the relay calls `splice_opaque_streams_capped`, whose own doc
comment states the property: *"The relay stays blind: bytes are counted, never
parsed."* The body is a userspace `read` → `write` loop over `&[u8]`.

- `admin/rust/server-rs/src/claw_share_rendezvous_stream_relay.rs` L572–582
  (doc), L583–612 (signature and buffers)

### 2.2 What it cannot see

Noise terminates at the two **endpoints**, never at Relay-R. The protocol is
`Noise_NK_25519_ChaChaPoly_BLAKE2s`. The prologue — which embeds the offer CBOR
— is a `snow` handshake **input** and is never written to the wire; handshake
messages carry empty payloads and a non-empty read payload is a hard error
(`UnexpectedHandshakePayload`).

- `admin/rust/household-rs/src/claw_share_relay_stream_noise.rs` L29 (protocol
  name), L32–36 (`TAG_LEN = 16`, `FRAME_HEADER_LEN = 4`)

The public relay binary's entire import list is the config, the listener, the
status handle, `axum`, `subtle`, and `tokio`. **No Noise symbol is imported at
all** — the blindness is a package-graph fact, not a discipline.

- `admin/rust/server-rs/src/bin/relay_stream_public_relay.rs` L21–33

Consequently Relay-R never sees `claw_id`, `slot_id`, `guest_device_pub`,
`resource`, `expected_path`, the owner signature, or any household identity.
All of those are fields of `RelayStreamOfferPayload`, which travels out-of-band
to the guest and never crosses the relay wire.

- `admin/rust/household-rs/src/claw_share_relay_stream_contract.rs` L105–139

**Relay-R is resource-blind, and that is verified, not inferred.** The relay
cannot distinguish an `IpTunnel` session from a `Pty` or `ClawSite` session,
because the type does not exist on its side of the boundary:

| relay-side file (`origin/main`) | `RelayStreamResource` references |
|---|---|
| `claw_share_rendezvous_stream_relay_listener.rs` | exactly **two** — L910 (an import) and L998 (a test fixture). `#[cfg(test)]` begins at **L905**, `mod tests {` at L906, so **both are inside the test module** and neither exists in the built binary |
| `bin/relay_stream_public_relay.rs` | **0** |
| `claw_share_relay_stream_public_relay_config.rs` | **0** |
| `claw_share_rendezvous_stream_relay.rs` | **0** |
| `claw_share_relay_stream_abuse.rs` | **0** |

> **An `IpTunnel` session rides the same relay, on the same port, with no new
> infrastructure, no protocol change, and no firewall change.** The relay sees a
> 4-byte header, a token, and two byte streams — identically for every resource.

Two things this does **not** license. It does not license reusing the Share
*configuration* for VPN: the byte cap and lifetime differ by orders of magnitude
and a shared process would have to take the looser value for both, which is why
§8 still specifies a separate Relay-R **process**. That is a tuning decision, not
a protocol one. And it does not license metering at the relay: resource-blindness
is the same property as principal-blindness, and ending one ends the other
(§6 L1).

### 2.3 What it unavoidably does see

| observable | source | retention | logged? |
|---|---|---|---|
| Source IP of both ends | `listener.accept()` at L183; `RelaySourceBucket::from_ip(peer_addr.ip(), …)` at L201–204 | In-memory abuse table, `source_state_ttl = 300 s`, ≤ `max_source_buckets = 4096` | **No.** `peer_addr` appears at exactly two sites in the listener (L184 binding, L202 use) and neither is a `tracing` call |
| That two source IPs share one token — a full social-graph edge at IP level | the pairing itself | duration of the splice | pairing is logged; the addresses are not |
| The rendezvous token, in **cleartext** | it is the pairing key; structural, not a defect | pending table ≤ `token_ttl`; consumed table `token_ttl` after spend | `Debug`/`Display` are redacted to `rendezvous-token(len=N, redacted)` — `claw_share_rendezvous_token.rs` L64–78 |
| Exact per-direction byte totals, live | `SpliceByteLedger` credits every accepted `poll_write` | process lifetime (in-memory counters) | yes, at `debug`, on every splice close |
| Session start, end, and duration | splice task lifetime | — | yes, at `debug` |
| Termination reason (`Closed` / `IdleTimedOut` / `LifetimeElapsed` / `ByteCapExceeded` / failed) | the four `tracing::debug!` arms at L505–571 | — | yes, at `debug` |

- IPv4 buckets on the **full** address; IPv6 is masked to `/64` by default
  (`ipv6_source_prefix_len = 64`) —
  `admin/rust/server-rs/src/claw_share_relay_stream_abuse.rs` L17, L25–39
- Aggregate counters `bytes_guest_to_claw` / `bytes_claw_to_guest` are fields of
  the `/status` JSON snapshot —
  `claw_share_rendezvous_stream_relay_status.rs` L464–480

There is **no padding, no cover traffic, and no mixing**, and the fixed-shape
Noise handshake makes the protocol trivially fingerprintable. No NAT-traversal
or hole-punching implementation exists in the tree.

### 2.4 The second relay, Relay-N, is **not** blind

`publish_household_log_entry` base64-encodes the raw `LogEntry` CBOR and
publishes it as Nostr event content with **no encryption**, tagged
`h = <household_id>` in cleartext, kind 30100. The crate's own doc comment
concedes it verbatim: *"Production hardening includes NIP-44 wrapping with a
per-household symmetric key so the relay sees opaque ciphertext; the slice ships
unencrypted … privacy at the relay is a separate (documented) follow-up."*

- `admin/rust/nostr-relay-rs/src/lib.rs` L48–57 (kind + doc), L302–319 (publish)

Two amplifiers:

- The engine's Nostr key is persisted at `<state_dir>/nostr_engine_key.hex`, so
  the publishing pubkey is **stable across restarts** —
  `admin/rust/server-rs/src/claw_share_relay_loop.rs` L51–55.
- The gossip subscribe logs `relay = <url>` and `hh_id = <id>` at **INFO** —
  same file, L306–316.

Relay-N is operator-configured and may be third-party. **Requirement 4 ("must
see NOTHING of the user") is contradicted by shipped code on this path today.**

> **Named blocker B-RELAY-N.** No plan may cite "the relay layer is private"
> while Relay-N ships unencrypted. The remedy the crate already names — NIP-44
> wrapping with a per-household symmetric key — is a prerequisite for any public
> launch claim about relay privacy, not a follow-up. See §9 and §10.

### 2.5 The blindness claim, stated so it survives inspection

> **Relay-R cannot read what is carried. It can see who is talking to whom,
> when, for how long, and how much.**

That is the sentence to use in product copy and in every other plan. The
unqualified phrase *"the relay sees nothing of the user"* is falsifiable from
this repository in ten minutes and must not ship.

For Share the distinction is tolerable: sessions are short, occasional, and
carry a page. For a VPN it is materially larger — a continuous, precisely-timed
record of one user's total traffic volume against a stable peer address is a
traffic-analysis dataset even without a single decrypted byte. Say so in the
VPN plans rather than reusing Share's framing.

---

## 3. Current limits, and which of them are wrong for packets

### 3.1 Relay-R listener defaults

`RendezvousStreamRelayListenerConfig::default()` —
`claw_share_rendezvous_stream_relay_listener.rs` L56–69. Env bounds from
`claw_share_relay_stream_public_relay_config.rs` L100–108.

| knob | default | env upper bound | tuned for | correct for packets? |
|---|---|---|---|---|
| `hello_timeout` | 5 s | 60 s | both | yes |
| `token_ttl` | 60 s | 3600 s | both | yes |
| `max_pending` | 1024 | 1,000,000 | both | yes — **but see the `max_consumed` footgun, §3.4** |
| `max_active_connections` | 2048 | 1,000,000 | both | yes, subject to an **unmeasured** process fd limit (§11 Q3) |
| `reaper_interval` | 10 s | 3600 s | both | yes |
| `splice_idle_timeout` | 300 s | 86,400 s | PTY / page fetch | **NO — structural no-op**, see §3.3 |
| `splice_max_lifetime` | 3600 s | 86,400 s | PTY / page fetch | **NO — kills a VPN hourly** |
| `splice_max_bytes_per_direction` | `None` generic; `Some(72 MiB)` in PUBLIC mode | no upper bound; may not be 0 in public mode | page fetch | **NO — kills a VPN in ~58 s at 10 Mbit/s**, see §4.2 |

The 72 MiB public cap is an **inclusive policy floor**: an explicit override
below it fails startup with `RelayCapBelowPolicyFloor`, and an explicit `0` is
rejected outright — a public relay may not run uncapped. There is **no upper
bound**, so any `u64 >= 72 MiB` is accepted. A compile-time
`const _: () = assert!(DEFAULT > PERSISTENT_MAX_BYTES_PER_DIRECTION)` fails the
**build** if the default ever regresses.

- `claw_share_relay_stream_public_relay_config.rs` L63 (constant), L73–75
  (compile-time assert), L364–390 (`parse_byte_cap`)

### 3.2 Relay-R abuse defaults

`RelayAbuseConfig::default()` — `claw_share_relay_stream_abuse.rs` L11–17,
L55–70.

| knob | default | note |
|---|---|---|
| `max_unpaired_active_per_source` | 16 | held between accept and parked hello |
| `max_pending_per_source` | 16 | a source may park only 16 waiting connections |
| `max_hello_attempts_per_source_per_window` | 120 | window = 60 s |
| `max_failed_hellos_per_source_per_window` | 30 | window = 60 s |
| `max_paired_splices_per_source` | `Some(128)` | settable to `None` only via the literal words `disabled`/`none`; `0` is rejected |
| `hello_attempt_window` | 60 s | |
| `source_state_ttl` | 300 s | |
| `max_source_buckets` | 4096 | |
| `max_splice_lifetime` | 3600 s | |
| `ipv6_source_prefix_len` | 64 | IPv4 buckets on the full address |

**These are abuse controls, not capacity knobs. Do not relax them to make a
capacity number look better.** The CGNAT collision they create for a consumer
VPN is a real problem and needs a design fix, not a raised constant — §7.3.

### 3.3 Endpoint-side limits (these do **not** run on Relay-R)

| knob | value | where |
|---|---|---|
| responder `auth_deadline` | 15 s (env max 300 s) | `claw_share_relay_stream_responder_config.rs` L22–25 |
| responder `idle_timeout` | 300 s (env max 3600 s) | same |
| data-tunnel `STREAM_IDLE_TIMEOUT` | 1800 s | `claw_share_data_tunnel.rs` L728 |
| `PERSISTENT_MAX_TARGET_OPENS` | 128 | `claw_share_data_tunnel.rs` L275 |
| `PERSISTENT_MAX_BYTES_PER_DIRECTION` | 64 MiB | `claw_share_data_tunnel.rs` L276 |
| `ReopenLimiterConfig` | 8 dials / 60 s per `(claw_id, guest_device_pub)`; table 65,536; idle TTL 300 s | `claw_share_relay_stream_reopen_limiter.rs` L48–57 |
| `WorkerPoolConfig` | `per_item_parked = 1`, `max_total_connections = 16`, backoff 100 ms…5 s | `tunnel-wire-rs/src/worker_pool.rs` L153–161 |

**The critical structural fact.** Both persistent budgets are gated on
`allows_persistent_targets`, which is
`offer.payload.resource == RelayStreamResource::ClawSite`
(`claw_share_relay_stream_session.rs` L72 and L110). And the reopen limiter's
module doc says verbatim: *"`IpTunnel` — Product A/nvpn's T1 datapath — and
`Pty` never reach it."* (`claw_share_relay_stream_reopen_limiter.rs` L13–14).

> **For `IpTunnel`, Relay-R's own caps are the only resource bound in the entire
> system.** There is no endpoint byte budget and no per-principal rate limit on
> the VPN datapath today. That is simultaneously the capacity problem (§4) and
> the reason the entitlement seam has nothing to attach to (§6, lever L1).

### 3.4 The `max_pending` / `max_consumed` footgun

`max_consumed` is **hardcoded at 4096** and is **not env-tunable**. The listener
builds the token table with
`max_consumed: RendezvousTokenTableConfig::default().max_consumed`
(listener L172, the file's only occurrence), and the public relay config never
mentions it (`grep -c max_consumed` on that file returns `0`).

Every expired **parked** token inserts a consumed entry (`prune_expired` →
`mark_consumed_best_effort`, `claw_share_rendezvous_stream_relay.rs` L170–183,
L239–241), and `mark_consumed` **never evicts a live entry** — at capacity it
returns `false` and a real pairing is rejected `ConsumedCapacityExceeded`
(L219–232, L214–217).

`max_pending` is env-settable up to 1,000,000. Setting it at or above 4,096 lets
**park-expiry alone** saturate the consumed table, at which point legitimate
pairings fail closed and **no env var exists to compensate.**

> **Decision D-RELAY-1 (delegated, T1 class).** Before any capacity tuning is
> authorized, either add an env for `max_consumed`, or validate
> `max_pending < max_consumed` at config parse and fail startup. Owner: the
> relay lane. This is a fail-closed correctness fix, not a limit relaxation.

---

## 4. Per-session cost model

### 4.1 What one paired session costs on Relay-R

Measured from the structs in `origin/main`, not estimated. **Every anchor below
names its file and its enclosing symbol**; an earlier revision of three rows
carried bare line numbers with no path, which cannot be resolved by a reader and
do not survive a rebase. `listener` = `admin/rust/server-rs/src/claw_share_rendezvous_stream_relay_listener.rs`;
`relay` = `admin/rust/server-rs/src/claw_share_rendezvous_stream_relay.rs`.

| resource | per paired session | evidence |
|---|---|---|
| file descriptors | **2** (one TCP socket per side; no pipes — the copy is userspace) | `listener::serve_rendezvous_stream_relay_with_status` accept path; `relay::splice_opaque_streams_capped` takes two streams |
| tokio tasks | **1** (the splice task spawned at the pairing site) | `listener::handle_rendezvous_stream` — the `tokio::spawn` at listener L495. The parked side's accept-task already returned on `Parked`; the pairing side's task returns after spawning |
| timers | 2 — a re-arming idle sleep and `sleep(max_lifetime)` | the two non-pump arms of the `select!` in `listener::splice_opaque_streams_until_idle` (`wait_for_idle(...)` and `sleep(max_lifetime)`, listener L662–691). Their two durations are supplied one frame up, at the `splice_opaque_streams_until_idle` call inside `handle_rendezvous_stream` (listener L496–502) |
| `max_active_connections` permits | **2** | `Arc::clone(&active_connections).try_acquire_owned()` at listener L194, immediately after **every** `listener.accept()` at listener L183 — both inside `serve_rendezvous_stream_relay_with_status` |
| `max_paired_splices_per_source` counters | 2 | two `listener::acquire_paired_splice` calls before the spawn |
| userspace heap | **32,768 B**, eagerly allocated, held for the whole session | `SPLICE_CHUNK = 16 * 1024` at relay L570; `guest_buf` and `claw_buf` at relay L606–607, inside `splice_opaque_streams_capped` |
| consumed-table entry | 1 (16…128-byte token + `u64`), for `token_ttl = 60 s` after pairing | §3.4 |
| everything else | `SpliceByteLedger` = 2 × `AtomicU64` (16 B); one `Arc<StdMutex<Instant>>`; two permit wrappers | 3+ orders of magnitude below the 32 KiB buffers |

**Kernel socket memory is not in this table because nobody has measured it.**
The Share plan itself names it as the likely dominant term and lists `ss -m` as
an S0 metric; no result is committed anywhere in the repository. See §11 Q1.

### 4.2 Wire framing overhead — exact, derived from code

`write_frame` issues **two** `write_all` calls: a 4-byte big-endian length, then
the encoded `TunnelFrame` (`claw_share_data_tunnel.rs` L300–319). The Noise
`AsyncWrite` adapter turns **each** `poll_write` into **one** Noise record of a
4-byte header plus ciphertext, where ciphertext = plaintext + a 16-byte
ChaChaPoly tag (`claw_share_relay_stream_noise.rs` L251–258, L596–612).
`TunnelFrame::Data` encodes as 1 tag byte + payload
(`tunnel-wire-rs/src/tunnel_wire.rs` L416–430).

For one IP packet of **N** bytes:

```
record 1 (length prefix) = 4 + (4 + 16)       = 24        wire bytes
record 2 (frame)         = 4 + (1 + N + 16)   = N + 21    wire bytes
--------------------------------------------------------------
total                                          = N + 45   wire bytes
```

| packet size N | wire bytes | overhead on payload |
|---|---|---|
| 1280 (the value the responder advertises) | 1,325 | **+3.52%** |
| 576 | 621 | +7.8% |
| 64 (a bare in-tunnel ACK) | 109 | **+70.3%** |

#### Where 1280 actually comes from — corrected

An earlier draft of this document cited
`admin/rust/claw-share-bridge-rs/src/lib.rs` L1150 (`assert_eq!(ns.mtu, 1280)`)
as **measured — the bridge asserts it**. That was wrong, and the correction
matters. In `origin/main`, `#[cfg(test)]` is at bridge L983 and `mod tests {` at
L984; L1150 is therefore inside the test module, as are **every** other 1280 in
that file (L1202, L1221, L1249, L1270, L1375, L1385). They are a loopback
self-test's fixtures, not a production assertion. The bridge's production path
does not pin an MTU at all — it destructures `mtu` out of `TunnelAck::Ok` at
L521–524 and passes it straight through to the caller (L541 `mtu,` in
`StartSessionOutcome`). **The bridge asserts nothing about MTU in a shipped
build.**

The real production source of 1280 is the responder, and it is a bare literal
written twice with no shared constant:

- `admin/rust/household-rs/src/claw_share_data_tunnel.rs` **L861** — `mtu: 1280`
  inside `TunnelAck::Ok`
- same file **L1039** — `mtu: 1280` inside `NetworkSettings`

(`#[cfg(test)]` in that file begins at L1324, so both are production code.)

#### The wider defect: the MTU disagrees across the tree, four ways

| value | site (`origin/main`) | status |
|---|---|---|
| **1280** | `claw_share_data_tunnel.rs` L861, L1039 | production literal, written twice, **not a named constant** — what the client is *told* |
| **1250** | `household-rs/src/claw_vpn.rs` L19 `CLAW_VPN_V1_INNER_MTU`, enforced at L1221 (`packet.len() > CLAW_VPN_V1_INNER_MTU` → `PacketTooLarge`) and sized into the read buffer at `server-rs/src/claw_vpn_packet_pump.rs` L19 (`+ 1`) | production constant — what the packet policy actually *allows* |
| **1280…9000, default 1400** | `t1-iptunnel-dev-runner-rs/src/main.rs` — the `gen-device-config` `--mtu` arg: `#[arg(long, default_value_t = 1400)]` at **L158** (the annotated `mtu: u16` field is L159), validated at L351, L440, L734 | dev-runner session config — a **third** value, and the range's floor is the responder's fixed value |
| **none** | the interface itself | the setup argv installs **no MTU**: Linux is `ip addr add … peer … dev`, `ip link set … up`, `ip route replace …`; macOS is `ifconfig <if> inet <a> <b> netmask … up`, `route -n add -host …` (`server-rs/src/claw_vpn_interface_route_plan.rs` L560–671). No `mtu` argument on either platform, and `grep -i mtu` returns **zero** hits in that file, in `claw_vpn_linux_tun.rs`, and in the dev runner's `dev_datapath` module body |

> **Named risk R9 (see §9).** The responder tells the client **1280**; the packet
> policy drops anything over **1250**; the dev config carries **1400** by
> default; and **nothing ever sets the interface MTU**, so the tunnel device
> keeps the kernel default. A packet in the 1251…1280 window is inside the
> advertised MTU and outside the policy ceiling. It is **latent, not live**
> today — the T1 mount is preflight-gated and the pump is reachable only through
> the dev runner — but it becomes live on the day T1 activates, and it will
> present as unexplained loss, not as an error.

**What this does and does not do to the cost model.** It is tempting to say the
cost model rests on an unpinned constant. It does not rest on it *much*:
`wire_factor` is 1.036 at 1250, 1.0352 at 1280, 1.0321 at 1400, and 1.0300 at a
1500 default — a **0.6% spread across all four values**, well inside the noise of
the V1–V3 premises. The cost model's real sensitivity is not to the MTU constant
but to the **packet-size distribution** (§6 L6, §11 Q4, checkpoint C5): a bare
ACK costs 70% overhead, and no number of correct MTU constants fixes that. R9 is
a **correctness** defect, and it is filed as one. It is not a reason to distrust
§4.6 or §4.7.

Define the **wire factor**:

```
wire_factor = (mtu + 45) / mtu          # = 1.0352 at mtu = 1280
```

Because Relay-R's cap counts **wire** bytes, the 72 MiB public cap admits only:

```
payload_per_direction = 72 MiB × mtu / (mtu + 45)
                      = 75,497,472 × 1280 / 1325
                      = 72,933,120 B = 69.55 MiB
```

…at full-size packets, and materially less on small-packet traffic.

### 4.3 How long a VPN session survives today's public defaults

| bound | value | time to hit at 10 Mbit/s payload | at 1 Mbit/s |
|---|---|---|---|
| byte cap, 72 MiB/direction | 69.55 MiB payload | **~58 s** | ~9.7 min |
| hard lifetime | 3,600 s | 1 h | 1 h |
| idle timeout, 300 s | — | **never fires** | never fires |

`splice_idle_timeout` — the Share plan's cheapest cost control — is a
**structural no-op for VPN**: `ActivityTrackedStream::mark_activity` timestamps
every poll in either direction
(`server-rs/src/claw_share_rendezvous_stream_relay_listener.rs` — the method at
**L719** inside `impl<S> ActivityTrackedStream<S>`, called from `poll_read` at
**L857** in `impl<S: AsyncRead + Unpin> AsyncRead for ActivityTrackedStream<S>`
and from `poll_write` at **L873** in
`impl<S: AsyncWrite + Unpin> AsyncWrite for ActivityTrackedStream<S>`), and VPN
traffic is continuous. Only the byte cap and the hard lifetime bound a VPN
session.

Both time bounds are capped at 24 h
(`MAX_SPLICE_IDLE_TIMEOUT = MAX_SPLICE_LIFETIME = 86,400 s`, public config
L105–106). The byte cap has no upper bound and cannot be set to unlimited in
public mode.

> A VPN deployment needs a **distinct configuration profile**, not the Share
> profile with a larger number. See §8.

### 4.4 Ceiling 1 — concurrency

```
pairs_ceiling_per_node   = floor(max_active_connections / 2)      = 1,024
planable_pairs_per_node  = headroom × pairs_ceiling_per_node      = 512   (headroom = 0.5)
```

The `/2` is not a convention: the semaphore permit is acquired immediately after
**every** `listener.accept()` and one pairing is built from **two** accepted
streams. Verified at listener L183 (`accept`) and L194 (`try_acquire_owned`) in
`origin/main`.

> **Correction of record.** `docs/soyeht-share-apple-like-plan.md` L728–730 cites
> this proof as `:182` → `:193`. In `origin/main` those anchors have drifted:
> L182 is `tokio::select! {`, L183 is the `accept`, L193 is a closing brace, and
> the acquire is at L194. The **claim is still true**; only the anchors moved.
> Do not copy the old line numbers forward.

At the 1,024-pair ceiling: userspace splice buffers total **32 MiB**
(1024 × 32 KiB ≈ 34 MB) and file descriptors total **~2,053**. Against the real
instance that is **3.5% of the 961 MB total**, or **5.4% of the ~622 MB actually
free** with 339 MB already resident (console read, 2026-08-06). At the planable
512 pairs it is 16 MiB ≈ 17 MB, i.e. 2.7% of free memory.

Those percentages are small, and they are also **not the number that matters**:
they count only the userspace buffers. Kernel socket memory — the term the Share
plan itself names as likely dominant — is unmeasured (§11 Q1), and 622 MB of
headroom is a materially tighter budget for it than the 1 GiB this document
previously assumed. The 0.5 headroom rule is doing that work implicitly; C2 is
what would let it be set from evidence instead.

### 4.5 Ceiling 2 — sustained pairing rate

Previously unstated, and it is not a memory or CPU limit.

```
consumed_insert_rate_max = max_consumed / token_ttl = 4096 / 60 = 68.3 inserts/s
park_expiry_rate         = max_pending  / token_ttl = 1024 / 60 = 17.1 inserts/s
pairing_rate_headroom    = 68.3 − 17.1                          = 51.2 pairings/s
```

Steady-state consumed-table occupancy is `insert_rate × token_ttl`. Both a
completed pairing and an **expired parked token** insert one entry. Past the
threshold, real pairings fail closed with `ConsumedCapacityExceeded`.

For Share this is generous. For a mobile VPN it is not obviously so:
reconnection after a handoff, a sleep/wake, or a network change is a **new**
rendezvous with a new consumed entry, and the 3,600 s lifetime forces a
reconnect at least hourly per session. At 512 concurrent sessions with an hourly
forced reconnect, baseline pairing rate is `512/3600 = 0.14/s` — comfortable —
but mobility churn is unmeasured (§11 Q5).

### 4.6 Ceiling 3 — egress, and the inversion

Assumption stated so it can be attacked: **billable egress ≈ the sum of both
directions.** Relay-R receives each byte from one side and sends it to the
other, so each carried byte egresses exactly once; ingress is assumed free.
If the provider bills ingress too, every figure below **doubles**. This must be
confirmed against the actual metering (§11 Q6).

> **Direction convention, stated once and used everywhere below.**
> `payload_GB_per_user_month` (premise V2) is the **sum of both directions** —
> everything the user's tunnel carries in a month, uplink plus downlink, counted
> once. It is *not* per-direction. Under this convention each such byte crosses
> Relay-R once inbound and once outbound, and only the outbound leg is assumed
> billable, so `relay_egress = payload × wire_factor` with **no factor of 2**.
> If V2 is ever re-sourced from telemetry that reports the two directions
> separately, **add them before substituting**; substituting a single direction
> halves every figure in §4.7.

```
relay_egress_GB_month = users × payload_GB_per_user_month × wire_factor

mean_concurrent  = users × hours_per_user_day / 24
peak_concurrent  = mean_concurrent × peak_to_mean
nodes_concurrency = ceil( peak_concurrent / planable_pairs_per_node )
```

**The load-bearing price identity — and it survived the account read.** At
~US$5.00/month per instance (account-read) with ~1 TB included and
~US$0.005/GB overage (**plan spec, not account-read** — see the provenance
table at the top):

```
1,000 GB × US$0.005/GB = US$5.00 = the price of one more instance
```

One instance's included transfer costs **exactly** one instance — the same
identity the previous draft derived at US$7.00 / US$0.007, and it is not a
coincidence: the vendor prices overage so that a terabyte and a node cost the
same. Buying a node and buying 1 TB of overage cost the same, and the whole
model collapses to a single expression:

```
cost_USD_month ≈ 5.00 × max( nodes_concurrency , relay_egress_TB )
```

Because the identity is preserved, **every ratio, trigger, and threshold in this
document is unchanged by the price correction** — the ~48-user S4 trigger, the
~629 MB budget line, the 0.5 headroom asymmetry, and the shape of §4.7 all
depend on the 1 TB allowance and on `wire_factor`, not on the price. What
changes is only the absolute dollar figure, which falls by 29%.

…where the egress term is *not* discounted by the 0.5 headroom rule, because
overage is linear and has no cliff, whereas concurrency has one. That asymmetry
is a decision, recorded here: **apply headroom to concurrency, buy overage for
egress.** Applying headroom to both would double the bill for no safety gain.

### 4.7 Worked scenarios

Premises, stated so they can be attacked. These are **assumptions**, not
measurements; replace them with telemetry before any decision rests on them.

| premise | value | status |
|---|---|---|
| V1 tunnel hours per user per day | 8 | assumption |
| V2 payload GB per user per month | 10, **summed over both directions** (see the convention in §4.6) | assumption |
| V3 peak-to-mean concurrency | 2× | assumption |
| V4 MTU | 1280 | **advertised by the responder** as a bare literal (`claw_share_data_tunnel.rs` L861, L1039) — **not** measured, **not** asserted by the bridge, and **contradicted** by three other values in the tree (§4.2, R9) |
| V5 wire factor | 1.0352 | **derived** from `N + 45`; spread across all four candidate MTUs is only 0.6% |
| V6 planable pairs per node | 512 | **configured, not measured** — see §11 Q1 |
| V7 instance price | ~US$5.00/month | **account console, 2026-08-06** |
| V8 included transfer / overage | ~1 TB / ~US$0.005/GB | **published plan spec, NOT account-read** — the load-bearing pair, and the least verified |

| users | peak concurrent | nodes by concurrency | relay egress | egress in TB | binding term | cost / month | per user |
|---|---|---|---|---|---|---|---|
| 100 | 67 | 1 | 1,035 GB | 1.04 | **egress** | ~US$5.18 | US$0.0518 |
| 1,000 | 667 | 2 | 10,352 GB | 10.35 | **egress** | ~US$51.8 | US$0.0518 |
| 10,000 | 6,667 | 14 | 103,520 GB | 103.5 | **egress** | ~US$518 | US$0.0518 |
| 100,000 | 66,667 | 131 | 1,035,200 GB | 1,035 | **egress** | ~US$5,176 | US$0.0518 |

In the egress-bound regime the marginal cost is flat and simple:

```
per_user_USD_month = 0.005 × wire_factor × payload_GB_per_user_month
                   = 0.005176 × payload_GB_per_user_month
```

**~5.2 US cents per user per month at 10 GB.** At 20 GB it is **~10 cents**.

That number is the one to hand the tiers plan, and the honest way to hand it over
is with its own consequence attached: **it is too small to price against.** No
plausible packaging decision turns on 5 cents. Read the table by the *column that
moves* rather than the total — the binding term is egress in every row, and every
row is cheap. Being egress-bound and being expensive are different properties,
and this workload has the first without the second.

**What that costs the argument for a byte budget.** The previous draft justified
§6 L1 ("a per-user byte budget") as *the* control on the binding cost term. With
the corrected rate that justification largely collapses: metering a user to save
5 cents is not worth a mechanism. What does **not** collapse is the tail. The
same formula says a single user pushing **10 TB/month costs ~US$52** — a
thousand typical users' worth of egress from one principal, with nothing in the
system to notice. So the byte budget survives, **re-purposed**: it is a fair-use
and abuse ceiling, not a pricing meter. §6 L1 is rewritten on that basis and
§6.0 re-ranks the constraints accordingly.

**Where the Share headline inverts.** The Share plan concludes *"Egress is not
the binding constraint at P5 = 64 KiB in any scenario — concurrency is"*
(`docs/soyeht-share-apple-like-plan.md` L779–780). Share's assumed session is
64 KiB total; a modest VPN user at 10 GB/month moves **~150,000×** that per
month (`10 × 10^9 / 65,536 ≈ 152,600`). Every row above is egress-bound. **The
conclusion does not transfer, and must not be copied into a VPN plan.**

The inversion is best stated as a formula rather than an opinion: the **per-user
byte budget that keeps egress non-binding**.

```
users_per_node    = planable_pairs / (hours_per_user_day / 24 × peak_to_mean)
budget_payload_GB = (headroom_egress × allowance_GB) / (users_per_node × wire_factor)
```

Instantiated with V1–V6 (`planable_pairs = 512`, 8 h/day, peak-to-mean 2×,
`headroom_egress = 0.5`, `allowance_GB = 1000`, `wire_factor = 1.0352`):

```
users_per_node    = 512 / (8/24 × 2)          = 768 users
budget_payload_GB = 500 / (768 × 1.0352)      = 0.629 GB ≈ 629 MB / user / month
```

Above ~629 MB per user per month, **egress binds and concurrency work is wasted
engineering.** The V2 premise of 10 GB/month is ~16× past that line, so it is not
a marginal call — but note the budget is inversely proportional to
`users_per_node` and therefore highly sensitive to V1 and V3. At 8 h/day with no
peak factor the same arithmetic gives ~314 MB; re-derive it rather than quoting
either number.

---

## 5. Verification of the numbers against the recorded S0 result

The only capacity result the product has is **prose in a follow-up document**.
No JSON, no `/status` snapshot, no CPU or RSS sample, and no configuration
record is committed anywhere in the repository.

`docs/followup-share-relay-hardening-2026-08-05.md` L42–58 states the run
*"establishes a demonstrated floor of 1,000 concurrent pairs for its temporary
elevated test configuration; it did not discover a capacity ceiling"* and warns
*"Do not extrapolate a maximum capacity from the completed 1,000-pair rung."*

Two reasons that figure must not enter a VPN plan as a capacity claim:

1. It was reached with **per-source caps temporarily raised**. The harness
   documents that a single host cannot exceed 128 paired splices otherwise, and
   that rungs above it *"will fail, and that is a limit measurement, not a
   capacity measurement"* (`admin/rust/server-rs/examples/relay_stream_s0_load.rs`
   L34–51). A run whose admission settings differ from production measured a
   different system.
2. It measured **idle or near-idle pairs**. A VPN pair is never idle. §11 Q2 is
   the measurement that would make the number transferable, and it has not been
   run.

---

## 6. Cost levers, ranked by impact

Ranked for the **VPN** workload. The Share plan's own ranking (S1 buffers,
S2 `splice(2)`, S3 io_uring) is correct for Share and wrong here, because it
optimizes the term that stops binding.

### 6.0 — What actually binds, ranked by what fails first

The account read (2026-08-06) forces a re-ranking, and the re-ranking only makes
sense once **what breaks** is separated from **what costs**. Those are different
orderings and merging them is how the previous draft over-weighted egress.

| # | constraint | ranked here because | status |
|---|---|---|---|
| **1** | **The 72 MiB splice cap** | It **terminates the tunnel in ~58 s at 10 Mbit/s** (§4.3). It is not a cost constraint; it is the reason the product does not function. Nothing below it can be observed until it is lifted, which also means **no measurement of 2–4 is possible today** | Fix is §8's VPN profile — a prerequisite, not a lever (L3) |
| **2** | **Per-instance throughput: 1 vCPU of *userspace* splice** | 1 vCPU is account-read. The copy is a userspace `read`→`write` loop over 16 KiB chunks (§4.1) — not `splice(2)`, not zero-copy. At MTU 1280 the loop wakes roughly once per 12 packets, ~80 wakeups/s/direction/session at 10 Mbit/s (§11 Q2). Console load average is **0.06**, which measures an idle relay and therefore says nothing about this | **Unmeasured.** Checkpoint C4 |
| **3** | **Concurrent sessions inside 961 MB** | 339 MB is already resident, leaving ~622 MB. Userspace buffers at 512 pairs are ~17 MB (2.7%); **kernel socket memory is entirely unmeasured** and the Share plan calls it the likely dominant term | **Unmeasured.** Checkpoints C1, C2 |
| **4** | **Monthly transfer** | Last, and deliberately so. Egress is the term that *grows the node count*, but at ~US$0.005/GB the absolute bill is ~5 cents/user/month at 10 GB. **It never breaks the service; it only bills.** The console meter reads 0.11% on a two-day-old account — no live signal | Bounded, cheap, and the only one with a known price |

Two things to hold onto from that table:

- **Constraints 2 and 3 are unmeasured *and* unmeasurable today**, because
  constraint 1 kills every session before either can be exercised. That is the
  strongest argument in this document for landing the VPN profile (L3) on a dev
  host first: it is not a tuning nicety, it is the precondition for having any
  capacity evidence at all.
- **Egress moved to last on cost, not on binding.** §4.7 is unchanged: every row
  is still egress-bound in the sense that egress, not concurrency, sets the node
  count. The re-rank says that mattering costs cents. Do not read §4.7 as saying
  transfer is expensive, and do not read §6.0 as saying transfer is free.

### L0 — Direct path: the session that never touches Relay-R

**This is the direct-path question, and it goes first because a session that
never reaches Relay-R costs nothing at all** — not egress, not a permit, not an
fd, not 32 KiB.

*Current state, measured.* There is **no direct-path attempt anywhere**. The
signed offer carries exactly one `relay_endpoint: String` and no candidate list,
no direct address, and no fallback field
(`claw_share_relay_stream_contract.rs` L107–139). Every session splices. The one
"direct" transport in the tree, `TunnelHandle::Direct { host, port }`, is
disqualified by its own doc: *"`Direct`/`Loopback` are dev / same-LAN
convenience and MUST NOT be the product path for a remote friend (no NAT
traversal)"* (`admin/rust/household-rs/src/claw_share.rs` L133–141).

*Impact.* At the hole-punch success rate the Share plan already cites — 70%
± 7.1% (arXiv:2604.12484, ACM IMC 2026) — direct-first removes ~70% of both
egress and concurrency. On the §4.7 table, 100,000 users falls from ~US$5,176 to
roughly **US$1,550/month**. No other lever in this document is within an order
of magnitude of that.

*And L0 is the only lever whose case is unaffected by the price correction.*
Every other lever here was ranked against a cost term that turned out to be
cents; L0 removes the session from the relay entirely, so it also removes
constraints 2 and 3 of §6.0 — the two that are unmeasured and that actually
break things — not just constraint 4. **The cheaper egress turns out to be, the
*more* L0 dominates the ranking, not less**, because its value was never
primarily the transfer bill.

*The trigger already exists and a VPN workload fires it immediately.* The Share
plan's spike shortlist row S4 reads: *"direct-first + invisible relay fallback |
— | **Only** if measured egress exceeds 50% of the 1 TB allowance, or workloads
grow materially. Otherwise not run."* (`soyeht-share-apple-like-plan.md` L898).
Per §4.7 a VPN workload crosses 50% of one node's allowance at **~48 users**.

*What it costs.* The always-relay decision is a **privacy** decision, and its
stated justification is Share-specific: *"A direct path would reveal the owner's
**residential IP to the guest**, contradicting the product promise that a friend
uses the app without entering the owner's home … Stated as the trade it is: we
decline a real concurrency saving to avoid leaking the owner's IP."* (L900–909).

That premise is about a **stranger guest**. It does not transfer to
device↔device VPN between a user's **own** devices, where both endpoints belong
to one principal and no third party learns anything. Resolve by **scope, not by
deletion** — quote the original sentence, and state that its premise does not
hold in the new scope. (The device↔device mesh plan owns that resolution; this
document supplies the cost case for it.)

*What is not blocked.* The offer payload is **structurally ready** for an
additive direct-candidate field. Two fields — `authz` and `app_presentation` —
already use `#[serde(default, skip_serializing_if = "Option::is_none")]`, whose
documented property is that an offer omitting the field encodes **byte-identically
to before the field existed**, preserving canonical CBOR, the owner signature,
and every cross-language fixture (`claw_share_relay_stream_contract.rs`
L119–138). The usual "we cannot change the offer" objection does not apply.

*Even at full success, keep the relay.* 30% of pairs fail hole-punching, so
Relay-R stays provisioned regardless. Direct-first reduces the bill; it does not
remove the layer.

### L0b — User-operated overlay transport (`Overlay-U`)

**The mode is defined in `docs/product-a-per-claw-vpn-plan.md` §12 and is not
re-resolved here**; §12.3 holds the per-mode security table, and this section is
only the cost case. (This heading previously carried one of the spellings §12's
registry retires. It is `Overlay-U` everywhere now.)

Same mechanism class as L0: for a user on `Overlay-U`, the session never reaches
Relay-R and the marginal cost is **zero**. Per owner decision, such a user is
fully supported and pays nothing — which is the tiers plan's `Overlay-U` tier
position (its §2), reached here from the cost side rather than the packaging
side.

*What already ships.* `core-rs::network_detect::detect_tailscale` shells out to
`tailscale status --json`, reads `Self.TailscaleIPs`, and reports a
`ChannelStatus` (`admin/rust/core-rs/src/network_detect.rs` L302–360); the admin
UI already renders an expose action for the tailscale channel
(`admin/frontend/src/pages/NetworkPage.tsx` L90, L94). This is not greenfield.

*What is blocked, stated precisely.* `parse_relay_endpoint` returns a
`(String host, u16 port)` and does **not** require an IP literal
(`claw_share_relay_stream_endpoint.rs` L26–67) — the strict IP-literal rule
applies only to the relay's own **bind** address (public config L318–332). So a
mint *can* point `relay_endpoint` at a mesh-reachable name. But both peers still
meet at a relay **process**: the protocol has no listener-on-one-peer mode.
"Meet over the user's own mesh" therefore needs a **rendezvous change**, not just
a different string. Do not describe it as a configuration tweak.

### L1 — A per-session byte ceiling (a fair-use backstop, **not** the entitlement seam)

**This lever changed name and purpose after the account read, and the change is
the point.** The previous draft called it "the entitlement seam" and justified it
as the control on the binding cost term. At ~US$0.005/GB that justification is
gone: a byte budget that saves 5 cents per user per month is not worth a
mechanism, and it is certainly not worth a pricing architecture.

What survives is the tail. §4.7's own formula says one principal at 10 TB/month
costs ~US$52 — a thousand typical users of egress from a single account — and
nothing in the system observes it. That is an **abuse and fair-use** problem, and
it wants a fixed ceiling, not a meter.

**Relay-R is structurally incapable of metering per user, and that has not
changed.** It counts bytes per *splice* and has no principal identity — it never
sees `claw_id`, `slot_id`, `resource`, or `guest_device_pub` (§2.2). Making
Relay-R the meter means **ending its blindness**. Do not do it.

The ceiling must live at the **endpoint**, where
`PERSISTENT_MAX_BYTES_PER_DIRECTION` already has exactly the right shape: a
constant compiled into the responder, enforced locally, reported to nobody.
Today it is gated on `resource == ClawSite` and so excludes `IpTunnel` (§3.3).
The work is: extend that budget from `ClawSite`-only to a **resource-keyed**
budget covering `IpTunnel`, and extend the reopen limiter — already keyed on
`(claw_id, guest_device_pub)` — to cover `IpTunnel` too.

#### Alignment with the tiers plan, which owns the entitlement seam this round

**This document is normative for the byte ceiling; the tiers plan is normative
for the entitlement chokepoint.** The two descriptions of the handoff were
worded differently in an earlier round and the difference was load-bearing — see
the mechanism block below. Tiers §8.1 now carries that block **byte-identical**
to the copy below and cites this section as normative for the mechanism; its own
box adds only tiers-side framing around it, outside the shared lines.

`docs/soyeht-tiers-and-entitlement-plan.md` **§5.0** ("The chokepoint, stated
once, for all three plans") chooses **one entitlement value, produced once at
`RelayStreamIssuerTrust::verify_offer_with_context` and ANDed into the
relay-stream authorization decisions that already exist**, rather than a new
mechanism. Its §8
("What is metered: transport, not intent") meters on **transport, not volume**: a
classifier over the signed `relay_endpoint` answering only "is this a
Soyeht-operated relay?". Its §9 ("The counted unit") counts live `shareable_apps`
rows, and singles out a **time-bounded** free period as the shape that needs no
counter at all. And its §10 ("Privacy: what the billing layer may learn") states
a prohibition in terms:

> **No usage telemetry as a billing input.** Per-session, per-byte, or
> per-endpoint metering would require the relay to observe what it is
> structurally built not to observe. Quotas must be enforced client-side against
> a signed number, not server-side against an observed one.

**This document defers to that resolution, and the earlier draft's second meter
is withdrawn.** There is now no conflict, for a reason worth naming rather than
asserting: L1 as re-scoped is not a billing input and produces no telemetry.

> **The mechanism, stated once — carried byte-identical by tiers §8.1.**
>
> A **resource-keyed endpoint byte budget**: extend
> `PERSISTENT_MAX_BYTES_PER_DIRECTION` from `ClawSite`-only to a resource-keyed
> budget covering `IpTunnel`, and extend the reopen limiter — already keyed on
> `(claw_id, guest_device_pub)` — to cover `IpTunnel` too. It is **a constant
> compiled into the responder, identical for every user, enforced locally,
> reported to nobody, never signed, and never seen by Relay-R or by
> `Issuer-E`.** It lives at the endpoint — **never on the relay**, which must
> stay blind. It is a **fair-use and abuse ceiling, not a pricing meter.**

That is the same shape `PERSISTENT_MAX_BYTES_PER_DIRECTION` already ships in for
`ClawSite`. It satisfies the tiers plan's §10 prohibition as written, because
there is no per-user observation anywhere in it.

**The mismatch that made this worth pinning.** The tiers plan's §8.1 previously
described the same mechanism as *"keyed on the principal the reopen limiter
already uses, **applied exactly when the attribution predicate says
`Relay-R`**"* (quoted with the retired alias `Relay-S` normalised to `Relay-R`).
Read literally that is a different mechanism: a ceiling switched
on by an entitlement-derived predicate is a per-user, entitlement-varying
quantity, and the compliance argument in the paragraph above — *no per-user
observation anywhere in it* — does not survive it. Both documents now state the
ceiling as **unconditional**: it applies to every `IpTunnel` session regardless
of entitlement, exactly as the `ClawSite` budget does today. Attribution decides
**chargeability** (tiers §8.2, §8.4); it does not switch this ceiling on and off.
If a future edit reintroduces the conditional wording in either document, it is
that document's defect, and T-METER below is where it would surface.

#### The residual tension, named rather than smoothed over — **T-METER**

The alignment holds **only while the ceiling is one constant for everyone.** It
breaks the moment packaging wants *differentiated* volume — "500 GB free, 5 TB
paid". At that point the ceiling stops being a compiled constant and becomes a
per-user number that has to be delivered to the endpoint, and the tiers plan's
boolean cannot carry a number.

The tiers plan already contains the only mechanism that could: its §9.2 option
(i), where `Issuer-E` signs a short-lived assertion **quoting quota `N`** against
a blinded household pseudonym, with the client enforcing `N` locally. That is a
number, not a boolean, and it is the meeting point of the two designs.

So the honest statement is: **the tiers plan's mechanism can deliver a
volume-differentiated byte budget only via its own §9.2 option (i).** If
packaging turns out to be volume-shaped, that plan's chosen entitlement value has
to carry a quantity rather than a verdict, and that is a change to **their**
design, not to this one. This document does **not** specify it, and explicitly
does not specify a second meter.

*Citation discipline for this subsection.* That document is uncommitted and was
under concurrent revision — its §5 was restructured while an earlier version of
this section was being written, which is how the two descriptions diverged in
the first place. Everything above is therefore cited by **section number and
title**, never by line number. The mechanism paragraph is now pinned verbatim in
both documents rather than paraphrased in each, and the tiers plan tracks the
same fork as its **O-9**. Re-read it before acting on this paragraph; if the
shape has moved, T-METER is the thing to re-check, not the wording.

*What would settle T-METER:* a single owner decision on packaging shape — is the
free/paid distinction **transport-shaped** (`Overlay-U` vs Relay-R, tiers §8), **count-
shaped** (live shared apps, tiers §9.1), **time-shaped** (a free period, tiers
§9.2 option iii), or **volume-shaped**? Only the fourth requires option (i), and
only the fourth creates the tension. **Given §4.7 — 5 cents per user per month —
volume-shaped packaging is the one shape the economics give no reason to
choose.** Recorded as a recommendation, not a decision: pricing is the owner's.

### L2 — Multiplexing (long-lived claw↔relay connection)

*What it saves.* Today one token = one TCP pair = one splice; 2 fds and 32 KiB
die with the session. Worse, a claw parks `per_item_parked = 1` connection per
offer (up to `max_total_connections = 16`), and Relay-R **drops** a parked
connection when the reaper prunes it at `token_ttl` — so a claw with K live
offers re-dials Relay-R roughly K times every 60–70 s **forever, at zero user
traffic**. A DERP-style long-lived connection carrying many logical sessions
removes both the churn and the per-session fd pair, and roughly doubles the
concurrency ceiling by ending the two-permits-per-session accounting.

*Why it ranks here — and this ranking moved.* The previous draft placed L2 below
L1 on the grounds that it saves "fds, permits, and dial churn — not egress", and
that egress was the binding term. Under §6.0 that argument no longer works:
fds, permits and dial churn are constraints **2 and 3**, which rank *above*
transfer on what fails first. The dial churn is the sharpest part — a claw with
K live offers re-dials Relay-R roughly K times every 60–70 s **at zero user
traffic**, which is load on the 1 vCPU that no user is paying for and no byte
counter reflects.

L2 nonetheless stays below L1 and far below L0, for a different and weaker
reason: **it is the only lever here with no implementation of any kind in the
tree**, its benefit is against two constraints that are themselves unmeasured
(C2, C4), and L0 removes ~70% of the sessions it would multiplex. Re-rank L2
upward if and only if C4 shows the 1 vCPU binding before 512 sessions — that
measurement, not the cost model, is what should decide it.

### L3 — VPN configuration profile (byte cap and lifetime)

Not a saving; a **prerequisite**. Without it the product does not function
(§4.3). Raising the byte cap *increases* cost by removing an accidental limiter.
Listed here so it is not mistaken for a lever. See §8.

### L4 — Buffer sizing, `splice(2)`, io_uring

The Share plan's S1/S2/S3. Whole prize at the 1,024-pair ceiling is ~16 MiB of
userspace memory (`32 MiB → 16 MiB`), plus a CPU improvement that is unmeasured
for continuous traffic. `splice(2)` needs a pipe pair, i.e. **4 extra fds per
paired session** (6 total instead of 2), and the kernel's pipe-user-pages soft
limit permits roughly 1,024 default-capacity pipes. **Zero egress impact.**
Correctly ranked last for VPN; keep the Share plan's own kill criteria.

### L5 — Sharding

Does not reduce cost; it converts a capacity wall into linear cost. It needs
**no new mechanism**: `relay_endpoint` is inside the **signed** offer, so the
shard is chosen at mint time and baked in — guest and claw always meet on the
same relay with no runtime coordination, no shared table, and no consistent
hashing. Accepted consequence, already recorded in the Share plan: losing a
shard invalidates the offers minted for it until they expire; the mitigation is
short invite TTLs, not HA.

### L6 — MTU / small-packet efficiency

`wire_factor` at MTU 1280 is 1.0352; across **all four** values the tree
actually carries (1250 / 1280 / 1400 / kernel default) it ranges 1.036…1.030 —
a **0.6% spread**, and at ~5 cents per user per month that is a rounding error
on a rounding error. **Do not change the MTU for cost.**

Change it for correctness instead. R9 (§9) is a real defect — 1280 advertised,
1250 enforced, 1400 defaulted, and no interface MTU set at all — and it will
present as unexplained packet loss when T1 activates, not as an error. That is a
correctness ticket that happens to touch the same constant, and it must not be
argued for or against on cost grounds.

The genuine cost sensitivity here is not the MTU but the **packet-size
distribution**: a bare in-tunnel ACK costs **70%** overhead (§4.2). If the real
workload is ACK-heavy the effective wire factor could be far above 1.035 and
every figure in §4.7 moves — by much more than any MTU choice. This is a
**measurement**, not a lever, until §11 Q4 is answered.

---

## 7. Where the owner's four requirements are in tension

The four stated requirements are: **highly scalable**, **must see nothing of the
user**, **minimum possible monthly cost**, **maximum users / highly efficient**.
They are not jointly satisfiable at every point. Where they collide, this is the
trade taken.

| pair | in tension? | where it bites | trade taken |
|---|---|---|---|
| blind × cheap | **Aligned** on the biggest lever | The cheapest lever (L0 direct path) *removes* the relay from the session entirely, so it reduces what any relay could see. It trades **peer-to-peer address disclosure**, not relay blindness | Take L0 for same-principal device↔device; keep always-relay for stranger-facing Share |
| blind × **monetizable** | **Largely dissolved by the price correction** | The previous draft called this the sharpest tension, on the premise that charging per user needs a per-user **byte** meter. At ~5 cents/user/month there is nothing to meter for revenue, so the tension only returns if packaging is deliberately made volume-shaped (**T-METER**, §6 L1) | **The tiers plan owns this and its answer is a boolean, not a meter** — `entitled(ctx)` at admission and liveness, classified on transport rather than volume. This document specifies **no meter**. The byte ceiling that remains (§6 L1) is a compiled constant enforced at the endpoint, reported to nobody, and therefore not a billing input at all |
| blind × scalable | **Yes** | Abuse controls bucket by **source IP**. Behind carrier CGNAT, thousands of unrelated mobile users share one bucket and therefore share `max_pending_per_source = 16` and `max_paired_splices_per_source = 128` — a denial of service against exactly the population a consumer VPN targets | **Do not relax the caps.** The real fix is an authenticated admission token that shifts bucketing from IP to principal — which moves identity toward the relay. That is a **design change with a privacy cost**, and it must be decided explicitly, not tuned into existence (§9 R3) |
| blind × operable | **Yes** | There is **no egress accounting** at all: the `/status` counters are in-memory, non-persisted, non-exported, and un-alerted. To plan or to bill, counters must be retained — and retaining them is a metadata-retention decision | Retain **aggregates only** (totals, session counts), never per-source or per-token rows. Aggregates answer the capacity question without building a per-user record |
| cheap × max users | **Yes** | The 0.5 headroom rule doubles the node count | **Apply headroom to concurrency, not to egress** (§4.6): concurrency has a cliff, overage is linear |
| scalable × blind (Relay-N) | **Contradicted today** | Relay-N ships **unencrypted** household-log gossip under a stable pubkey (§2.4) | Blocker B-RELAY-N. NIP-44 wrapping before any public launch claim about relay privacy |

**The one sentence to carry forward.** Every mitigation that adds a per-user
meter, a principal-keyed admission token, or direct-path candidates moves
information toward the relay or toward the offer. Each such step trades against
the blindness the product is built on. Make the trade **explicit, one line per
mechanism**, rather than letting it accumulate silently — an entitlement seam
that ends up keyed at the relay would quietly convert a blind splicer into a
per-user accounting service.

---

## 8. Configuration profiles: Share vs VPN

T1 activation decisions are delegated. This section says what **will** be done
and by whom; it asks nothing of the owner.

| knob | Share profile (today's public defaults) | VPN profile (proposed) | reason |
|---|---|---|---|
| `splice_max_bytes_per_direction` | 72 MiB | large, sized from the per-user budget rather than guessed — **the value is set only after §10 C3 measures real per-session bytes** | 72 MiB kills a VPN session in ~58 s at 10 Mbit/s (§4.3). Must remain a finite cap: the parser rejects `0` in public mode, correctly |
| `splice_max_lifetime` | 3,600 s | 86,400 s (the hard maximum) | 1 h forces an hourly reconnect. 24 h is the ceiling; **>24 h sessions are structurally impossible today** — reconnection must be designed, not assumed (§9 R4) |
| `splice_idle_timeout` | 300 s | leave at 300 s | It is a **no-op** for VPN (§4.3). Raising it would be theatre; document that it does nothing rather than tune it |
| `max_active_connections` | 2048 | **unchanged until the process fd limit is measured** (§11 Q3) | At a common 1024 soft limit the relay caps at ~511 pairs — half its configured ceiling — and nothing in the tree would reveal it |
| `max_pending` | 1024 | **unchanged** until D-RELAY-1 lands | Raising it toward `max_consumed = 4096` saturates the consumed table and fails real pairings closed (§3.4) |
| abuse per-source caps | defaults | **unchanged** | Abuse controls. The CGNAT problem is a design fix, not a tuning fix (§7, §9 R3) |

**Deployment shape.** The VPN profile is a **separate Relay-R process** with its
own environment, not the Share relay reconfigured. Two reasons: the byte cap and
lifetime differences are large enough that a shared process would have to take
the looser value for both; and separating them keeps a Share regression from
being caused by a VPN tuning change. Note that this is a **process** separation
and needs no protocol or network change — Relay-R is resource-blind (§2.2), so an
`IpTunnel` session would ride the existing relay on the existing port
untouched. The separation is bought purely for the tuning isolation above.

**But a second process is not free on this instance, and the account read says
so.** Relay-R is **1 vCPU / 961 MB with 339 MB already resident** (console,
2026-08-06). Two Relay-R processes on that box contend for the same single core —
which is §6.0's constraint 2, the highest-ranked *unmeasured* one — and for the
same ~622 MB. The separation is therefore correct as a **configuration** decision
and open as a **placement** decision: same instance or a second instance is not
settled here, and settling it needs C4. If C4 shows the 1 vCPU binding, a second
US$5 instance is the cheapest resolution in this entire document and should not
be treated as an escalation.

**Ordering note, and it is load-bearing.** §8's byte cap is written as "set only
after C3 measures real per-session bytes", and C3 needs real VPN traffic — which
today's 72 MiB cap terminates in ~58 s (§6.0, constraint 1). That is circular as
written. Break it deliberately: the dev-host VPN profile takes a **provisional**
finite cap chosen to be comfortably above any expected session, recorded as
provisional, purely so that C3 and C4 become measurable at all. The **final**
cap is then set from C3. What must not happen is the provisional value silently
becoming the production value because nobody re-ran C3 — the provisional cap is
part of the C2 configuration record specifically so that substitution is visible.

**Ownership.** The relay lane sets and validates the VPN profile on a dev-host
Relay-R instance and records the resulting configuration alongside the capacity
evidence. **Production activation, deploy, and flag flips remain separate
owner-authorized events.**

**Runtime posture is unchanged and stays fail-closed.** `THEYOS_RELAY_STREAM_PUBLIC_RELAY`
must be exactly `1|true|0|false`; the bind address must be a concrete IP literal
(loopback, wildcard, hostnames, and port 0 are each rejected with their own
typed error); the optional `/status` endpoint must be loopback-bound and requires
a bearer token file of ≥ 32 non-whitespace characters compared with
`subtle::ConstantTimeEq`; supplying only one of (status bind, token file) fails
closed. (`claw_share_relay_stream_public_relay_config.rs` L254–269, L307–345;
`bin/relay_stream_public_relay.rs` L138–172.) **None of this is relaxed by the
VPN profile.**

---

## 9. Named risks

Each of these is a risk to state loudly, not to design around quietly.

**R1 — Relay-N ships unencrypted (blocker B-RELAY-N).** Base64 cleartext
`LogEntry` CBOR, tagged with a plaintext household id, under a disk-persisted
stable pubkey, to an operator-configured and possibly third-party relay. This is
the sharpest contradiction of the "sees nothing of the user" requirement in the
tree, and it is shipped code, not a plan. Remedy is already named by the crate:
NIP-44 wrapping with a per-household symmetric key.

**R2 — the byte ledger under-counts on I/O error, and for VPN that becomes the
common case.** The listener's `Err` arm reports **no** bytes, because every `?`
inside the pump discards its local outcome and the arm has no ledger in scope.
The code marks it KNOWN DEBT deliberately (listener L533–549), and the status
module repeats it (`…relay_status.rs` L460–463). Under a VPN workload, peer
resets are the **normal** termination — mobile handoffs, sleep, network changes
— so the arm that under-counts becomes the ordinary path and egress telemetry
systematically under-reports. **That is a billing-relevant blind spot, not a
cosmetic one.** Any per-user meter built on these counters inherits it; this is
a second, independent reason the meter belongs at the endpoint (§6 L1).

**R3 — CGNAT source-bucket collision.** IPv4 buckets on the full address and
IPv6 on `/64`. Behind carrier NAT, unrelated mobile users share
`max_pending_per_source = 16`, `max_unpaired_active_per_source = 16`, and
`max_paired_splices_per_source = 128`. For a consumer VPN this is a denial of
service against legitimate users **by construction**. Do **not** relax the caps
— they are the abuse controls. The real fix is an authenticated admission token
that shifts bucketing from IP to principal, which is a design change with a
privacy cost (§7).

**R4 — no session can exceed 24 h.** `MAX_SPLICE_LIFETIME = 86,400 s`. If the
product promise is "the VPN stays up", reconnection must be **designed**, not
assumed. Reconnection is not free: a new session means a new rendezvous, a new
consumed-table entry (§4.5), and a fresh Noise handshake.

**R5 — the deployable public relay target has no required-features gate.**
`relay_stream_claw_dev` and `relay_stream_relay_dev` both carry
`required-features = ["dev_claw_share_mint"]`; `relay_stream_public_relay` does
not, and its Cargo comment says it *"is part of the deployable Share transport
surface"* (`admin/rust/server-rs/Cargo.toml` L20–42). Runtime is still default-off
via the env flag. Correct as designed — recorded so a future reader does not
"fix" it into a dev-only binary and break deployment.

**R6 — locating detail already published.** `docs/soyeht-share-apple-like-plan.md`
names a hosting **vendor and city** across several lines. That is not an IP or a
hostname, but it narrows an attacker's search for the relay to one provider in
one region, which is what the standing constraint exists to prevent. If a cost
model needs a price, an unnamed instance **class** carries identical arithmetic
with none of the location — this document does exactly that. **Decide
deliberately whether to keep the vendor naming; do not let it propagate into new
plans.**

**R7 — project-owned relay hostname committed as a test fixture.** A
`wss://` project relay hostname appears at two sites in `household-rs`
(`claw_share.rs` L2065 and `claw_share_relay.rs` L196). They are test fixtures,
but they publish a project-owned relay name in a public repository. Low
severity, trivially fixed with a `.invalid`/`.test` name. Sweep it together with
a real-looking CGNAT address that sits in a doc comment at
`admin/rust/core-rs/src/network_detect.rs` L248 as sample command output.

**R8 — the 1,000-pair figure will be quoted.** It was measured with per-source
caps temporarily raised, on idle pairs, with no committed artifact (§5). The
follow-up document already forbids extrapolating from it. **The temptation to
quote it in a VPN plan will be strong; it must not be quoted.**

**R9 — the MTU is unpinned, disagrees four ways, and is never applied to the
interface.** Measured at `origin/main` (§4.2):

- the responder **advertises 1280** — a bare literal written twice, at
  `household-rs/src/claw_share_data_tunnel.rs` L861 (`TunnelAck::Ok`) and L1039
  (`NetworkSettings`), with no shared constant between them;
- the packet policy **rejects anything over 1250** —
  `household-rs/src/claw_vpn.rs` L19 `CLAW_VPN_V1_INNER_MTU`, enforced at L1221
  as `PacketTooLarge`, and sized into the pump's read buffer at
  `server-rs/src/claw_vpn_packet_pump.rs` L19 as `+ 1`;
- the dev runner's session config **defaults to 1400** and accepts 1280…9000
  (`t1-iptunnel-dev-runner-rs/src/main.rs` **L158**, `#[arg(long, default_value_t =
  1400)]` on `gen-device-config`'s `mtu` field; validated L351 / L440 / L734) —
  a value that then **never reaches the interface or the pump**, since
  `new_claw_vpn_pollable_pump` hardcodes `CLAW_VPN_V1_INNER_MTU`
  (`server-rs/src/claw_vpn_pollable_pump.rs` L85);
- and **no setup path sets an interface MTU at all**. The Linux argv is
  `ip addr add … peer … dev`, `ip link set … up`, `ip route replace …`; the
  macOS argv is `ifconfig <if> inet <a> <b> netmask … up`,
  `route -n add -host …` (`server-rs/src/claw_vpn_interface_route_plan.rs`
  L560–671). `grep -i mtu` returns **zero** hits in that file, in
  `claw_vpn_linux_tun.rs`, and in the dev runner's `dev_datapath` module body.

**Consequence.** A packet of 1251…1280 bytes is inside the MTU the client was
told and outside the ceiling the policy enforces; the interface, keeping the
kernel default, will happily produce one. The failure mode is a **silent drop**,
surfacing as unexplained loss rather than an error.

**Severity and honest scope.** This is **latent, not live**, and the reason is
structural rather than configurational: `IpTunnel` is compiled out of a default
build (`IP_TUNNEL_RESOURCE_COMPILED = cfg!(any(test, feature =
"dev_t1_datapath"))`, `claw_share_relay_stream_offer_store.rs` L38), so a
production artifact rejects the offer with `ResourceCompiledOut` before any
packet exists. The mount additionally falls back to
`PerClawVpnT1PreflightEvidence::missing` when no preflight bundle is supplied
(`claw_share_relay_stream_mount.rs` L852) — but note that whether a *deployed*
instance supplies a bundle is runtime state this tree cannot establish, so the
compile-out is the load-bearing half of that argument and the preflight gate is
the second layer.

It becomes live the day T1 activates. **It is a correctness defect, not a cost
defect** — the wire-factor spread across all four values is 0.6% (§6 L6), so no
figure in §4 or §4.7 depends on resolving it. Fix it as correctness; do not let
it be argued on cost, and do not let the small cost impact be read as low
priority.

**The remedy is a pinned constant, not a chosen number.** One named constant,
one source of truth, with the advertised value, the policy ceiling, and the
interface configuration all derived from it — and a test that fails if any two
diverge. Do **not** resolve it by raising the 1250 policy ceiling to 1280: that
is relaxing a fail-closed packet filter to match an unpinned literal, which is
the wrong direction. Lower the advertised value to the enforced one, or raise
both together and set the interface to match.

---

## 10. Capacity and cost checkpoints before any public launch

Every checkpoint has an explicit PASS condition. A checkpoint that cannot be
evaluated from a committed artifact has not passed.

| # | checkpoint | PASS condition |
|---|---|---|
| **C1** | **Process fd limit is recorded.** No `LimitNOFILE`, `ulimit`, `setrlimit`, unit file, deployment manifest, or container spec exists anywhere in the tree (`git grep -rniE 'LimitNOFILE\|ulimit\|setrlimit' origin/main` returns **zero** hits) | The **actual** fd limit received by the running Relay-R process is read from the live process and committed alongside the configuration that produced it. PASS requires `limit ≥ 2 × max_active_connections + 16`. If the limit is lower, `max_active_connections` is reduced to match — **the configured ceiling never exceeds the fd ceiling** |
| **C2** | **S0 evidence is committed, not described.** The harness already emits one JSON object on stdout and a stderr progress marker so a collector can bracket `/status` and process samples; nobody captured it | The JSON, the before/after `/status` snapshots, process RSS and CPU, **and the exact configuration** (including admission settings and the fd limit from C1) are committed together. A capacity number whose configuration cannot be reconstructed is not evidence |
| **C3** | **Bytes per session, p50 and p95, per direction, from real traffic** — the input every cost row depends on. The only measured byte figure in the tree is a ~5.9 KB shared page, and the harness explicitly forbids quoting its own 1 KiB echo as product traffic | p50 and p95 recorded separately for Share and for VPN, from splice counters, over a window of at least 7 days. **VPN and Share figures are never averaged together.** Only after C3 is the VPN byte cap set (§8) |
| **C4** | **CPU under continuous traffic** — the single largest unknown, and no existing spike covers it (S0 measured idle pairs) | Measured at 1 / 100 / 256 / 512 concurrent **continuously active** sessions on the target instance class. PASS: 512 sessions hold with CPU < 60% and p95 added latency within the Share plan's own gate. If CPU binds before 512, `planable_pairs_per_node` in §4 is replaced by the measured figure and §4.7 is re-run |
| **C5** | **Effective wire factor is measured, not assumed** | Real packet-size distribution captured from a live tunnel; `wire_factor` recomputed from it. PASS: the measured factor is within 10% of 1.0352, **or** §4.7 is re-run with the measured value before any pricing decision |
| **C6** | **Egress accounting exists.** There is none today: no persistence, no export, no per-period rollup, no alerting. The Share plan's own upgrade trigger ("monthly transfer past 50% of included") has **no instrument behind it** | Aggregate byte counters are persisted across restarts, rolled up per period, and alert at 50% of the allowance. **Aggregates only — never per-source or per-token rows** (§7). The known I/O-error under-count (R2) is either fixed or the reported figure carries a stated error bound |
| **C7** | **Relay-N is encrypted** (blocker B-RELAY-N, §2.4) | NIP-44 wrapping with a per-household symmetric key ships, **or** no launch material claims relay-layer privacy. One of the two, explicitly chosen and recorded |
| **C8** | **`max_pending` / `max_consumed` is closed** (D-RELAY-1, §3.4) | Either an env for `max_consumed` exists, or config parse validates `max_pending < max_consumed` and fails startup. A negative test proves the failure path |
| **C9** | **The VPN profile is validated end-to-end on a dev host.** A client that can carry `IpTunnel` **does exist** — see the correction below | A `IpTunnel` session survives ≥ 24 h of continuous traffic under the VPN profile without hitting the byte cap or an unexpected termination, with the `/status` counters and termination reason recorded. **PASS additionally requires stating, with the result, which of the four gaps below were still open during the run** — a 24 h figure measured with software keys and a mint bypass is evidence about the datapath, not about production |
| **C10** | **The direct-path decision is recorded** (§6 L0) | Either S4 is run and its result committed, or a written decision states why an egress-bound workload will pay ~3× to keep always-relay. **Silence is not a decision** — the S4 trigger is crossed at ~48 users |
| **C11** | **The per-user budget seam exists** (§6 L1) | A resource-keyed byte budget covers `IpTunnel` at the **endpoint** or the **mint**. PASS requires a negative test proving the budget actually rejects — a positive test cannot catch a guard that stopped guarding |
| **C12** | **Public-repo hygiene sweep** (R6, R7) | The vendor/region naming decision is recorded; the project relay hostname fixtures and the sample CGNAT address are neutralized |
| **C13** | **The MTU is pinned to one constant** (R9, §4.2, §9) | One named constant is the single source of the advertised value, the policy ceiling, and the interface configuration; a test fails if any two diverge. Resolved by lowering the advertised value to the enforced one, or by raising both together and setting the interface — **never** by relaxing the 1250 policy filter alone |

### Correction to C9 — the client that does exist, and what is missing from it

An earlier draft said C9 needs "a client that can carry the resource", citing
only `friend-cli-rs`'s refusal. That refusal is real —
`admin/rust/friend-cli-rs/src/main.rs:1054`,
`bail!("relay_stream IpTunnel payload is not implemented in this client")`, with
three tests pinning that exact string at L1873, L1897, L1928 — but it was the
wrong client to look at, and the conclusion drawn from it was wrong.

**`t1-iptunnel-dev-runner-rs` exists and carries the resource.** Under
`--features dev_t1_datapath` it compiles a `RunDeviceDatapath` command whose
`dev_datapath` module imports `ClawVpnLinuxTunDevice` / `ClawVpnMacosUtunDevice`,
`claw_vpn_interface_route_plan`, and `claw_vpn_pollable_pump`, and which on
success prints `runner_tun_opened=true, runner_route_installed=true,
runner_packet_pump_started=true` (`src/main.rs` L1132–1141). It **opens a real
interface, installs real routes, and drives a real packet pump.** The serving end
exists too: `server-rs/src/bin/t1_iptunnel_claw_dev.rs`, same
`required-features = ["dev_t1_datapath"]` (`server-rs/Cargo.toml` L47–50).

*(The runner's own module doc at `src/main.rs` L1–8 still says it "does not
implement a local tunnel interface, route install, packet pump". That sentence
predates `RunDeviceDatapath` and is **stale under the feature**; the
`RunDeviceDatapath` doc at L112–116 contradicts it directly. Do not take the
module header as the current answer.)*

**What is missing from it — four gaps, each a stated limit on what a C9 PASS can
claim:**

1. **It is not a product client, and cannot become one by configuration.**
   `dev_t1_datapath` in `server-rs` is declared
   `dev_t1_datapath = ["dev_claw_share_mint"]` (`server-rs/Cargo.toml` L188), and
   `dev_claw_share_mint` is described in the same file as "an owner-authorization
   BYPASS fixture: production/release builds MUST NOT enable it". The only build
   that can carry `IpTunnel` is the same build that compiles in a mint bypass.
2. **The resource itself is compiled out of production.**
   `IP_TUNNEL_RESOURCE_COMPILED = cfg!(any(test, feature = "dev_t1_datapath"))`
   (`server-rs/src/claw_share_relay_stream_offer_store.rs` L38), enforced at L362
   `require_resource_enabled` via L352 `resource_enabled_for_build`. A default
   build rejects an `IpTunnel` offer with `ResourceCompiledOut`.
3. **The run is not production-representative in its key handling.** The runtime
   gates require **both** `THEYOS_T1_DEV_DATAPATH=1` and
   `THEYOS_FORCE_SOFTWARE_KEYS=1` (`t1-iptunnel-dev-runner-rs/src/main.rs`
   L40–42, checked in `validate_dev_datapath_runtime_gates_with_env`), plus an
   exact dev-host ack string and a **second** ack before it will dial a
   non-loopback relay. Forcing software keys means the measurement says nothing
   about hardware-keystore behaviour under load.
4. **There is no reconnection, which is exactly what a ≥ 24 h checkpoint needs.**
   `grep -ic 'reconnect\|redial\|retry'` over the runner returns **0**. The run
   is one session; when it ends it ends. Since `splice_max_lifetime` maxes at
   86,400 s (R4), a ≥ 24 h checkpoint is at the exact boundary where reconnection
   stops being optional — and the client that would have to perform it does not
   implement it.

**Restated PASS for C9.** Run it on the two-ended dev harness, and record the run
**with these four gaps named in the artifact**. C9 can establish that the
datapath carries continuous traffic for 24 h under the VPN profile. It cannot
establish anything about the production artifact, production key handling, or
reconnection, because none of those three is in the binary under test.

---

## 11. Open questions, each with the measurement that settles it

These are unresolved. They are written as questions rather than papered over.

**Q1 — What is the kernel-side memory per paired session?**
The userspace 32 KiB/pair is measured (§4.1); kernel socket memory is entirely
unmeasured, and the Share plan itself calls it the likely dominant term. Every
capacity figure in §4 is therefore **configured, not measured**.
*Settles it:* `ss -m` and process RSS sampled at 1 / 100 / 512 / 1024 pairs,
committed with the configuration (checkpoint C2).

**Q2 — Does 512 concurrent sessions hold under continuous traffic?**
The read loop wakes roughly once per 16 KiB — about 12 packets at MTU 1280 — so
at 10 Mbit/s that is ~80 wakeups/s per direction per session. Nothing measures
what 512 such sessions do to 1 vCPU. S0 measured the **wrong workload**.
*Settles it:* checkpoint C4.

**Q3 — What fd limit does the deployed process actually receive?**
Nothing in the repository defines one. At a common 1024 soft limit, Relay-R caps
at ~511 pairs — half its configured 1,024 — and no artifact would reveal it.
*Settles it:* checkpoint C1.

**Q4 — What is the real packet-size distribution, and therefore the real wire
factor?** 1.0352 assumes full-size packets. An ACK-heavy workload could push the
effective factor well above it, moving every figure in §4.7.
*Settles it:* checkpoint C5.

**Q5 — What is the mobile reconnection rate, and does it approach the pairing-rate
ceiling (§4.5)?** Baseline hourly-reconnect churn is comfortable at 512 sessions
(0.14/s against ~51/s of headroom), but handoff and sleep/wake churn is
unmeasured, and each reconnect also costs a fresh Noise handshake.
*Settles it:* count `paired_sessions` per hour against concurrent sessions on a
dev-host run with real mobile clients.

**Q6 — Does the provider bill ingress as well as egress, and is the allowance
really ~1 TB at ~US$0.005/GB?** §4.6 assumes ingress is free and each carried
byte egresses once. If ingress is billed, **every cost figure in this document
doubles.** The 2026-08-06 console read did **not** close this: it showed the
monthly transfer meter at **0.11% used on a two-day-old account** — a number
consistent with any metering rule, since almost nothing has flowed — and the
allowance and overage rate were **not visible on the pages read**. Those two
figures are carried in this document as **published plan spec, not measurement**,
and they are the two the entire cost model rests on.
*Settles it:* a billing-page read at the end of a month with non-trivial usage —
allowance, rate, and the direction rule — plus whether the meter is per-instance
or pooled across the account. A plan page does not settle it; a plan page is what
we already have.

**Q7 — Does the deployed relay actually run with the defaults in §3?**
Every number there is the code default or the env-parse bound; the live
configuration is outside the repository. The follow-up document makes the same
point: *"inspect the limits actually received by the running process and the
live admission settings, rather than relying only on declared unit or
configuration values."*
*Settles it:* checkpoint C2's configuration record.

**Q8 — Is aggregate-only retention sufficient to operate the service?**
§7 chooses aggregates to avoid building a per-user record. If an incident
requires per-source attribution, that choice will be tested.
*Settles it:* a written incident-response note stating what is *not* available
and what will be done instead — before the first incident, not during one.

**Q9 — Is the packaging shape volume-differentiated? (T-METER, §6 L1)** This is
the one open question in this document that only the owner can close, and it is
the only thing that would put this plan and the tiers plan back in conflict.
**It is the same question as that plan's O-9; neither document may close it
alone, and both must move together when it closes.** The
tiers plan's chosen mechanism is a **boolean**; a volume-differentiated tier
needs a **number** delivered per user, which exists in that plan only as §9.2
option (i) (`Issuer-E` signs an assertion quoting quota `N` against a blinded
pseudonym) and is not in its §12 build order.
*Settles it:* an owner decision on shape — transport-shaped, count-shaped,
time-shaped, or volume-shaped. Three of the four require nothing from this
document. **§4.7 gives no economic reason to pick the fourth: at ~5 cents per
user per month, differentiating on volume prices a term that is already
negligible.** Until it is answered, §6 L1 stays a single fixed ceiling and this
document specifies no meter.

---

## 12. Scope note on the measurement in this document

The relay surface read for this plan is the 30 files matching
`admin/rust/server-rs/src/claw_share_(relay|rendezvous)*` in `origin/main`:
**24,393 lines** containing **334** `#[test]` / `#[tokio::test]` attributes. The
listener alone is 2,247 lines with 33 tests; the public relay config is 1,028
lines; the abuse model 865; the token/splice core 1,454; the public relay binary
205.

That scope is **not** the same as the wider "relay_stream / Share" aggregate
quoted elsewhere (24,293 lines / 360 tests), which includes `household-rs` leaf
modules and `tunnel-wire-rs`. The difference is scoping, not disagreement. Where
this document quotes a size, it quotes **its own** scope with the scope stated.

**Three files outside that scope were read for specific claims** and are named so
the scope statement stays true: `household-rs/src/claw_vpn.rs` and
`server-rs/src/claw_vpn_{packet_pump,pollable_pump,interface_route_plan}.rs` for
R9's MTU chain; `t1-iptunnel-dev-runner-rs/src/main.rs` and
`server-rs/src/bin/t1_iptunnel_claw_dev.rs` for the C9 correction; and
`claw-share-bridge-rs/src/lib.rs` for the corrected provenance of MTU 1280.

**And one class of fact in this document is not code at all.** The instance
class, price, load, memory, and transfer meter are **account-console reads dated
2026-08-06** — outside the repository, unversioned, and unreproducible from this
tree. They are labelled at every use. The allowance and overage rate are weaker
still: **published plan spec, never read from the account**, and they are the two
figures the cost model most depends on (§11 Q6). A future reader re-deriving §4.6
must re-read the console rather than trusting these lines; a price is not a
commit.
