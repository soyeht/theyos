# Share ↔ Foundation Boundary Map

Triage reference for classifying server-rs / workspace test failures as
**Share**, **Foundation**, or **Boundary**. Built from `use`-edges and opened
source, not from filenames. Compiled while auditing `572ec5f7` (the `#423`
`fix/guest-image-gate-guard-scope` tip) before the `--no-fail-fast` list was
triaged.

## Scope of each side

### Foundation (shared base)
- **`core-rs`** — `error`, `ipc::protocol` (leases), `availability`, `pagination`,
  `manifest`, `artifact_*`, `guest_image_failure`, `guest_net`, `id`, `slug`,
  `time`, `retry`, `poll`, `instance_failure`, `boot_id`.
- **`tunnel-wire-rs`** (S0 neutral wire) — `pollable_pump`, `frame_stream`,
  `worker_pool`, `canonical`, `tunnel_wire`.

### Share (custom-domain Share feature)
- `handlers_claw_share.rs` — Share HTTP routes.
- `claw_share_relay_stream_*` — the Share relay (noise, rendezvous, offer store,
  trust, abuse, provision, session, reverse-connect pool).
- `claw_share_rendezvous_stream_relay*` — the blind byte splicer.
- `claw_share_pty_target.rs` — PTY share target.
- `owner_site_*` — custom-domain authority (resolution_store, authority,
  capability, challenge, ake).
- `cloudflare_*` — Cloudflare DNS/tunnel integration for custom domains.
- `public_sites.rs` — public claw site reverse proxy (boundary; see below).
- `claw-share-bridge-rs` — iOS bridge. **Insulated**: depends only on
  `household-rs` + `nostr-relay-rs`; no `core-rs` / `tunnel-wire-rs` edge.

## Contact points (real `use`-edges)

| # | Share site | Foundation edge | Class | Evidence |
|---|------------|-----------------|-------|----------|
| 1 | `claw_share_relay_stream_reverse_connect_pool.rs` | `tunnel_wire_rs::worker_pool` | **Boundary** | `:42,64,92,204,231` |
| 2 | `claw_share_rendezvous_stream_relay_listener.rs` | none — uses **local** `splice_opaque_streams_until_idle` | **Share** | `:582,597`; byte counts via `record_splice_closed(guest_to_claw, claw_to_guest)` |
| 3 | `claw_vpn_pollable_pump.rs` | `tunnel_wire_rs::pollable_pump` + `frame_stream` | **Foundation** | `:22,28,107` — ⚠️ this is `claw_vpn` (T1, feat `dev_t1_datapath`), NOT `claw_share` |
| 4 | `claw_store_service.rs` | `core_rs::manifest::{ClawInstallability, UnavailableReasonCode}` | **Boundary** | `:9-12` |
| 5 | `public_sites.rs` | `core_rs::error` + `store-rs` instances + `guest_net::public_site_host_port_range()` | **Boundary** | bridges custom-domain ↔ VM |
| 6 | `owner_site_*`, `cloudflare_*` | `core_rs::error` only | **Share** | custom-domain authority |

## Name-collision traps (open before classifying)

- **"guest" has three meanings:**
  - `guest_image_failure` / `guest_image_state` / `guest_net` (foundation) =
    **VM guest** (Firecracker/VZ — IPSW, MAC `06:00:ac:10:00:02`, TAP
    `tap0`/`tap1`).
  - `claw_share_rendezvous…acquire_paired_splice(&mut guest…)` (Share) =
    **share invitee**.
  - `public_sites::DEFAULT_GUEST_PORT` = port **inside the VM**.
- **"splice" / "pump" has two owners:**
  - `tunnel_wire_rs::pollable_pump` / `frame_stream` (foundation) — consumed by
    **`claw_vpn`**.
  - `splice_opaque_streams` local to the Share rendezvous listener — consumed by
    **`claw_share`**.
- **"claw_vpn" ≠ "claw_share"**: same prefix, different features. `claw_vpn` is
  the T1 datapath (`dev_t1_datapath` feature); `claw_share` is the Share relay.
- **Two reason-code enums:** `core_rs::manifest::UnavailableReasonCode` vs
  `core_rs::guest_image_failure::GuestImageFailureCode`. The latter's doc states
  it "mirrors `manifest::UnavailableReasonCode`". `claw_store` uses the manifest
  one; `instance_create` uses the guest-image one.

## Security ratchets — do NOT revert for green

These are intentional fail-closed / scoping decisions recorded as dated verdicts
in doc-comments. "Make it pass by relaxing the rule" reverts a security verdict
and is prohibited by the program objective (no weakening of gates, ratchets,
canonicality, signature, revocation, or fail-closed to obtain green).

- **`store_rs::InstanceDb::get_for_household_status`** — *"Strict rule (security
  verdict, 2026-08): a row without `household_id` belongs to NO household —
  unscoped rows are hidden here exactly as `list_for_household` hides them, so
  status and listing answer the same question the same way by construction.
  Legacy unscoped rows regain visibility only by being stamped via
  `stamp_mac_host_household`."* Adding a `None => Ok(Some(row))` legacy arm to
  make a status test go green **is the revert**. The Share integration's policy
  is "stamp, don't widen".
  **Executed in-commit, not just asserted:** `5b04e135` removed the
  `None if row.household_machine_id.is_none() => Ok(Some(row))` arm and inverted
  the unit test in place (`household_status_accepts_legacy_unscoped_rows` →
  `household_status_rejects_unscoped_rows`), with the comment *"Kept (not
  deleted) so the rule change is visible in review."* A deliberately inverted
  test is stronger evidence than a doc-comment (which can drift). SQL also
  enforces it: `list_for_household` filters `WHERE household_id = ?1`, and SQL
  `NULL` never satisfies `=` — unscoped rows vanish by query construction, not
  by an `if` that could diverge from the listing path.
  - Symptom: `household_instances.rs` `…status_allows_legacy…` expects 200 for
    an unscoped row and fails with 404; the adjacent `…actions_reject_legacy…
    ` test expects rejection of the same row class and passes. The status test
    is stale (left behind when `status` was tightened to match `actions`/`list`).
    Fix = update the test (expect 404, rename, cite the verdict), NOT the query.
- **`store_rs::InstanceDb::stamp_mac_host_household`** — the counterpart of the
  above: the seeded `mac-host` row is stamped with a household at engine start
  (once the household is known) rather than widening any query. Unscoped rows
  are invisible to the owner's Share picker by design.

## Method note

When a test fails, read the **doc-comment immediately above the mechanism**, not
just the function body. The reason a ratchet exists is usually stated in the
prose beside it (e.g. the `2026-08` verdict above `get_for_household_status`,
the struct-field comment at `household_bootstrap.rs:1366` explaining the
`.clone()` is for the Share relay-stream remounts). Slicing a function out with
an awk/regex range that starts at the `fn` line drops exactly that comment.
Extract with leading context (`sed -n 'START,ENDp'` over a range that includes
the comment block), or read the file directly.

## Classification key

- **Foundation:** `instance_create`, `guest_image_state`, `availability`,
  `capacity`, `lease_*`, `warm_pool`, `reconcile`, `install_worker`,
  `artifact_*`, `vmrunner-*`, and the `admin_guest_image_gate_guard` family.
- **Share:** `claw_share_relay_stream_*`, `claw_share_rendezvous_*`,
  `owner_site_*`, `cloudflare_*`, `handlers_claw_share`.
- **Boundary:** `public_sites`, `claw_store_service`,
  `claw_share_relay_stream_reverse_connect_pool`, `terminal-rs`
  (`claw_share_pty_target` depends on it).
- **Insulated:** `claw-share-bridge-rs` (no foundation edge; route through
  `household-rs` / `nostr-relay-rs`).
