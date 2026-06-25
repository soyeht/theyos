# Headless GROUP-VPN smoke runbook (Path A: off-LAN group claim → ack → dial)

Operator runbook for the off-LAN **Group** `relay_stream` path, driven entirely from
the CLI (no app). The code half (the shared group-op apply helper, the dev-gated
`/dev-group-op` seed endpoint, and the `friend-cli group-claim-relay` subcommand) is
lab-green; the **hardware run** below is a deploy step (rebuild + restart a dev engine,
run a guest). This is the proven, copy-pasteable sequence.

## What this proves (and what is NEW)

An earlier membership hardware smoke proved the **Group dial** over a live public relay
by minting the offer with the HTTP `dev-mint-relay-offer` / `relay-offer/group`
endpoints. This smoke proves the **off-LAN claim acquisition of that offer over the
Nostr relay store-and-forward path** — the CGNAT-immune Path A:

```
friend-cli group-claim-relay                 engine (dev profile)
  build member-signed binding + device PoP
  ClawShareClaim::sign_group (nonce == challenge)
  publish_encrypted_claim ──► nostr relay ──► relay loop process_one
                                              routes on group_request.is_some()
                                              handle_group_claim:
                                                project() live mesh log
                                                verify_group_claim (9 checks)
                                                  incl. check_relay_stream_group_membership
                                                try_provision_group_offer_for_claim
                                              ClawShareGroupAck (offer, credential-less)
  decode ClawShareGroupAck ◄── nostr relay ◄──  publish_encrypted_claim (NIP-44)
  run_relay_offer_session_dial ──► public splice relay ──► claw  (PTY marker)
```

Success = `relay_stream PTY payload ok: marker echoed` from friend-cli, plus
`claw_share.relay.group_claim_acked` on the engine.

The membership gate passes **only** because `/dev-group-op` seeded the live projection
from the **same** member/device secrets the friend-cli claim uses (identical
`member_id` + `device_pub`).

## Boundary (hard)

- **Dev profile only.** Use the dev engine label/port; leave the production engine and
  state untouched.
- **nvpn / Plane-3 (`10.44/16`) excluded.** This is Plane-1 community-relay only.
- `/dev-group-op` is feature- and runtime-gated (loopback +
  `THEYOS_DEV_CLAW_SHARE_INVITE_MINT=1` + `THEYOS_FORCE_SOFTWARE_KEYS=1`); the route and
  its types are absent from any build without `--features dev_claw_share_mint`.

## Topology

The PTY runs on the engine HOST (`claw_share_pty_target` ignores `claw_id`), so **no
real claw VM is needed**:

- **Engine** = a dev engine (loopback admin), rebuilt with `--features dev_claw_share_mint`.
  It runs the nostr relay-loop + the group handler + `/dev-group-op` + the relay_stream
  mount, and **reverse-connects out** to the splice relay. No deploy to the relay node
  is needed — only a local rebuild + restart of the dev engine.
- **Splice relay** = a community relay node with a reachable public `IP:port` (real
  inbound TCP — not a CGNAT-only host). Blind splicer: engine and guest both
  reverse/forward to it.
- **Nostr relay** (claim/ack store-and-forward) = any reachable public relay, e.g.
  `wss://nos.lol`.
- **Guest** = off-LAN (a cellular device, or any machine not on the engine's LAN)
  running `friend-cli group-claim-relay`. Reaches the claw purely through the splice relay.

## 0. Build

```sh
cd admin/rust
# Engine + dev bins WITH the dev fixture feature (the /dev-group-op route lives in the
# server-rs lib gated by this feature; any engine bin built with it picks up the route
# via household_bootstrap → handlers_claw_share::router).
cargo build --release -p server-rs --features dev_claw_share_mint
# Guest CLI (no feature needed; group-claim-relay is always compiled).
cargo build --release -p friend-cli-rs
```

Deploy the dev engine binary with the same rebuild+redeploy procedure used for the
other dev-mint fixtures (swap the binary + restart the dev label only). A new launchd
plist env var needs a full `bootout`/`bootstrap`.

## 1. Engine env (dev profile only)

| var | why |
|-----|-----|
| `THEYOS_FORCE_SOFTWARE_KEYS=1` | durable file keystore + a `/dev-group-op` gate |
| `THEYOS_DEV_CLAW_SHARE_INVITE_MINT=1` | the `/dev-group-op` + `dev-mint` gate flag |
| `THEYOS_RELAY_STREAM_LIVE=1` | claw mount + offer pool + `try_provision_group_offer_for_claim` returns an offer |
| `THEYOS_RELAY_STREAM_RELAY_ENDPOINT=<relay-public-ip>:<port>` | single-sources the offer's `relay_endpoint` (IP literal, not hostname) |
| `THEYOS_RELAY_STREAM_DEV_ALLOW_PUBLIC_RELAY_DIAL=1` | allow the mount to reverse-connect to a non-loopback relay (dev smoke) |
| `THEYOS_NOSTR_RELAY=<wss-relay-url>` | the engine relay identity subscribes here (relay-loop receives the group claim) |
| `THEYOS_CLAIM_RELAYS=<wss-relay-url>` | claim/ack relay set the engine advertises |

The **nostr relay** is where the friend publishes the claim and the engine is subscribed
(store-and-forward of claim/ack). The **splice relay** (`<relay-public-ip>:<port>`) is a
separate node used only for the dial/data path. Get the engine's **`owner_engine_npub`**
(the x-only hex of `<state_dir>/nostr_engine_key.hex`) — the guest needs it in step 3.

## 2. Seed the group (loopback, on the engine host)

`/dev-group-op` mints the binding server-side from the secrets and applies
`Create + AddMember + EnrollMemberDevice + GrantClaw` through the real `apply_group_op`.
Secrets ride the **body**, never the URL; nothing is logged.

```sh
curl -sS -X POST http://127.0.0.1:<admin-port>/api/v1/claw-share/dev-group-op \
  -H 'content-type: application/json' \
  -d '{
        "member_secret":  "<64-hex>",
        "device_secret":  "<64-hex>",
        "participant_npub":"<x-only-hex>",
        "group_id":       "group_alpha",
        "claw_id":        "claw_dev_smoke",
        "member_label":   "phone_alpha"
      }'
# → {"member_id":"g_…","device_pub":"03…","group_id":"group_alpha","claw_id":"claw_dev_smoke"}
```

`claw_id` may be any string, but it MUST be consistent between this call and step 3
(the group must have `GrantClaw` on it and `claim.claw_id` must match). The secrets here
MUST be identical to the `--member-secret`/`--device-secret` in step 3 (binding match).

## 3. Run the off-LAN guest claim

```sh
THEYOS_RELAY_STREAM_DIAL=1 DEV_ALLOW_PUBLIC_RELAY_DIAL=1 \
  ./friend-cli group-claim-relay \
    --relay         "<wss-relay-url>" \
    --engine-npub   "<engine owner_engine_npub, x-only hex or npub>" \
    --group         "group_alpha" \
    --claw          "claw_dev_smoke" \
    --member-secret "<same 64-hex as step 2>" \
    --device-secret "<same 64-hex as step 2>" \
    --npub          "<same participant_npub as step 2>" \
    --ttl-secs 600 --ack-timeout-secs 90 --verbose
```

- `THEYOS_RELAY_STREAM_DIAL=1` arms the credential-less dial of the received offer (default OFF).
- `DEV_ALLOW_PUBLIC_RELAY_DIAL=1` allows dialing a non-loopback relay addr.

## 4. Assert + collect

PASS criteria:
- friend-cli stdout: `member_id` equals step-2 `member_id`; `group ack ok — relay_stream
  offer received` (audience `Group { … }`); then **`relay_stream PTY payload ok: marker echoed`** (exit 0).
- engine log: `claw_share.relay.claim.event_received` → `claw_share.relay.group_claim_acked`
  → `claw_share.relay.claim.process_ok`. A rejection logs `group_claim_rejected` with a
  `reason=` and emits **no** ack.
- splice-relay log: the guest↔claw pairing/splice for the rendezvous token.

## 5. Teardown

Stop any standalone dev bins; leave production untouched; confirm the dev engine is
healthy (`healthz` 200). The dev household state is disposable.

## Gotchas

- **Single-use nonce.** Re-running with the same nonce inside the TTL is rejected as
  `NonceReplay` (shared across relays) — each `group-claim-relay` run generates a fresh
  nonce, so just re-run; don't replay a captured claim.
- **No ack on rejection.** A failed check is silent to the friend (the engine only logs
  `group_claim_rejected reason=…`); distinguish "no ack yet" from "rejected" via the
  engine log, not a timeout.
- **TTL capped at 600s** regardless of `--ttl-secs`.
- **Offer signer.** The group offer is machine-cert-chain signed (root-signed Group
  offers are rejected by `verify_with_trust`); the dev household must have a valid
  machine-issuer cert active in the projection.
- **Owner-independence.** Group claims are credential-less and route BEFORE the
  `owner_auth` guard in `process_one`, so a group member reaches the claw even when the
  owner identity is not loaded (a household without an owner PersonCert). The Device
  claim path still requires `owner_auth`.
- **device key everywhere.** `binding.device_pub == claim.guest_device_pub == device PoP
  signer == offer.guest_device_pub == dial key` — all one `--device-secret`.
