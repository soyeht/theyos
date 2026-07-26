# M1 household mesh smoke — Dev-only assisted runbook

This runbook binds the already-landed pair-machine, reachability probe, and
local iPhone-connection surfaces into one manual M1 demonstration. It adds no
runtime integration and grants no authority. The dedicated Rust binary is
read-only: it never pairs, installs, resets, migrates, launches, or stops an app
or engine.

The demonstration has three separate observations:

1. `mac-alpha` and `linux-alpha` are Ready MachineCert engines.
2. A fresh, exact 32-byte diagnostic echo succeeds in both directions.
3. The local UI says **“Paired iPhone connected to this Mac”** while the paired
   iPhone is connected to `mac-alpha`.

These observations must not be collapsed into “three devices online.”
`/machines` does not list the iPhone/DeviceCert, and the iPhone badge is local
WebSocket state for this Mac—not household presence.

## Safety boundary

- Use only `/Applications/Soyeht Dev.app`.
- The expected bundle id is `com.soyeht.mac.dev`.
- The only permitted macOS profile namespace is `SoyehtDev`.
- The macOS Dev engine is `http://127.0.0.1:8101`.
- Each role must have a local Tailscale IPv4. The preflight reads it only from
  the local Tailscale daemon, validates the CGNAT range, and never prints it.
- Use a dedicated Linux candidate with no household identity before the
  pair-machine ceremony.
- Run each role locally on that host. There is no SSH or remote-command mode.
- Do not reset, migrate, uninstall, reissue, or touch an existing household.
- Keep real machine names, addresses, IDs, and signer material only in an
  ignored local file such as `.env.m1-household-mesh.local`. Never paste them
  into a report or PR.
- Do not use a fallback signer or read internal state if owner-PoP signing is
  unavailable. Record **BLOCKED**.

A bare binary invocation is always safe. Build the isolated leaf package first:

```bash
cargo build --manifest-path admin/rust/Cargo.toml -p m1-household-mesh-smoke-rs
M1_SMOKE_BIN="$PWD/admin/rust/target/debug/m1-household-mesh-smoke"
```

Then invoke it without a subcommand:

```bash
"$M1_SMOKE_BIN"
```

It prints the plan and performs zero network requests and zero state changes.

## What the reachability signal means

The owner-PoP header controls access to `GET /api/v1/household/machines`; it
does not sign the returned `online` bool. For a non-self machine, that bool is
the result of an unauthenticated echo sent to a cached address. The self entry
is hardcoded `true` and is ignored by the binary.

The only approved description of a positive non-self result is:

> checagem diagnóstica de reachability passou na última atualização

The cache is merely the destination for a fresh CSPRNG challenge. Exact echo
matching makes failures collapse to `false`, but it does not authenticate the
peer. A poisoned cache that points at a different host running the echo
endpoint can produce a bounded false-positive. Therefore the result is never
proof of peer identity, membership, authority, presence, or VerifiedMesh.

In the UI, use the literal text `last probe: reachable` /
`last probe: unreachable` / `—` as the observation. Do not use the status-dot
color as evidence: the color remains ambiguous UX decoration.

## Prerequisites

- `mac-alpha`: Soyeht Dev.app installed, exact `SoyehtDev` namespace, Dev
  engine reachable on loopback port `8101`.
- `linux-alpha`: dedicated Linux VM or process host, household engine on
  loopback port `8091`, with no pre-existing household identity before join.
- Tailscale connectivity between the two engines.
- Existing external owner-PoP signer configured through the versioned
  `THEYOS_HH_POP_SIGNER_ARGV_JSON_V1` contract. Its value is a strict JSON
  array of non-empty, NUL-free strings: the first item is the absolute,
  already-canonical path to a non-symlink regular executable that is not
  group- or other-writable; the remaining items are literal arguments.
  Arguments are visible to local process inspection, so never put secrets,
  Authorization values, endpoints, machine IDs, or signer material in them.
  The signer must obtain any private material from its own approved secure
  store. These checks reject obvious executable misconfiguration; they do not
  eliminate every filesystem TOCTOU or establish custody of the executable.
- The legacy shell-string variable `THEYOS_HH_POP_SIGNER_CMD` is not read or
  executed by this binary. If it is present, verification is **BLOCKED**.
  Migrate the local ignored configuration to the V1 JSON argv contract before
  running this smoke.
- For the `/machines` GET the signer receives EOF (an empty body) on stdin and
  an otherwise empty environment containing exactly:
  - `THEYOS_HH_SIGN_METHOD`
  - `THEYOS_HH_SIGN_PATH`
  - `THEYOS_HH_SIGN_TARGET_ALIAS`

  Their values are fixed by the binary to `GET`,
  `/api/v1/household/machines`, and the neutral local role alias. The signer
  inherits no `HOME`, `PATH`, proxy, profile, token, or smoke configuration.
  A signer that requires inherited environment is **BLOCKED** under V1; a
  future requirement needs an explicit versioned contract.

  It must emit exactly one UTF-8 `Soyeht-PoP` Authorization line, optionally
  prefixed by `Authorization: `, terminated by a single LF. Missing or extra
  line endings, extra lines, controls, oversized output, timeout, and malformed
  output are **BLOCKED**. Stderr and signer output are never included in the
  report; the binary has no internal-signing fallback. The binary checks only
  the wire shape locally (`p_` id, timestamp, and an unpadded URL-safe base64
  signature decoding to 64 bytes). The server remains the authority that
  verifies the signature cryptographically.
- An operator physically present for the iPhone/Face ID owner ceremony.

Do not put real values in this document. A documentation-only local template
looks like:

```bash
# .env.m1-household-mesh.local (ignored; never commit)
export THEYOS_HH_POP_SIGNER_ARGV_JSON_V1='["/absolute/path/to/local-signer","--dev-profile"]'
export M1_PEER_BASE_URL='http://100.64.0.10:8091'
```

The address above is a neutral example. Use the actual peer Tailnet endpoint
only in the ignored local environment.

## 1. Read-only preflight

On `mac-alpha`:

```bash
"$M1_SMOKE_BIN" preflight --role mac
```

This requires the exact Dev app, bundle id, profile namespace, operating
system, local Tailnet IPv4, loopback engine, and `state: "ready"`.

On `linux-alpha`:

```bash
"$M1_SMOKE_BIN" preflight --role linux
```

If the candidate already has a household identity before the ceremony, stop.
Do not reset it for this test; create a separate disposable candidate.

## 2. Manual owner ceremony

This section is intentionally not automated.

1. Use the iPhone Dev build with bundle id `com.soyeht.app.dev` when it is
   available. Pair it through Soyeht Dev.app using the existing owner-key
   ceremony and complete the Face ID confirmation.

   If the only available iPhone build has bundle id `com.soyeht.app`, it may
   participate only in a ceremony visibly targeting the macOS `SoyehtDev`
   profile. Never reuse or open a production pairing link, session, or URL.
2. On the dedicated, identity-free Linux candidate, start the existing join
   ceremony:

   ```bash
   theyos install --pair-machine --transport tailscale --hostname-label linux-alpha
   ```

3. Complete the displayed pair-machine flow through Soyeht Dev.app and the
   iPhone owner approval. The CLI must refuse an existing household identity;
   do not bypass that refusal.
4. Wait until both MachineCert engines report Ready via their local preflight.
5. Separately observe the exact local badge text:

   > Paired iPhone connected to this Mac

   This proves only a paired iPhone is currently connected to **this Mac** over
   the local HMAC WebSocket. It is not a DeviceCert roster entry, remote
   household presence, membership, or a third “online” device. The badge is a
   separate required gate now that the surface is persisted: if the literal
   badge is unavailable, mark the local-connection gate **BLOCKED** even when
   the owner/Face ID ceremony itself passed. Do not invent remote iPhone
   presence or use ceremony success as a substitute.

## 3. Mac → Linux diagnostic verification

On `mac-alpha`, load the ignored local signer and set the Linux Tailnet
endpoint without echoing it:

```bash
set -a
. ./.env.m1-household-mesh.local
set +a
"$M1_SMOKE_BIN" verify --role mac --ack-dev-only
```

`--ack-dev-only` is a visible operator acknowledgement required only for
verification. It confirms that the operator deliberately selected this
runbook's Dev-only boundary; it is not a secret, authority, identity proof, or
substitute for the real preflight checks. Without it, verification is
**BLOCKED** before reading environment or constructing any adapter.

The role passes only if:

- the Dev-only preflight passes;
- the owner-PoP `/machines` view contains exactly one Mac and one Linux
  MachineCert, with the non-self diagnostic result positive; and
- a fresh 32-byte challenge returns HTTP 200, exact
  `application/octet-stream`, declared length 32, and identical bytes.

## 4. Linux → Mac diagnostic verification

On `linux-alpha`, provide the same signer convention locally and set
`M1_PEER_BASE_URL` to the Mac’s Tailnet household endpoint. Do not reuse the
Mac’s loopback URL.

```bash
set -a
. ./.env.m1-household-mesh.local
set +a
"$M1_SMOKE_BIN" verify --role linux --ack-dev-only
```

One role cannot claim bidirectional success. M1 diagnostic reachability passes
only when both local role reports contain `PASS M1-RESULT`.

## Evidence and disposition

Save only the binary’s sanitized stdout. It emits neutral aliases and status
facts; it never prints endpoints, addresses, IDs, Authorization values, or
response bodies.

Redacted PASS example:

```text
PASS M1-HOST        role=mac local=mac-alpha peer=linux-alpha — role matches the local operating system
PASS M1-MACHINES    role=mac local=mac-alpha peer=linux-alpha — owner-PoP query accepted; checagem diagnóstica de reachability passou na última atualização
PASS M1-ECHO-32B    role=mac local=mac-alpha peer=linux-alpha — exact 32-byte diagnostic round trip passed; no peer identity is inferred
PASS M1-RESULT      role=mac local=mac-alpha peer=linux-alpha — local role passed diagnostic gates; reciprocal role report is still required
```

Redacted BLOCKED example:

```text
BLOCKED M1-OWNER-POP role=linux local=linux-alpha peer=mac-alpha — external owner-PoP signer is required
```

Final manual record:

| Gate | Required evidence | Result |
|---|---|---|
| Dev isolation | Exact Dev app/bundle/namespace and local Ready on Mac | PASS / BLOCKED |
| Linux isolation | Dedicated candidate and local Ready | PASS / BLOCKED |
| Owner ceremony | Manual iPhone/Face ID approval completed | PASS / BLOCKED |
| Local iPhone connection | Exact “Paired iPhone connected to this Mac” badge; unavailable is BLOCKED | PASS / BLOCKED |
| Mac → Linux | Sanitized `PASS M1-RESULT` from `--role mac` | PASS / BLOCKED |
| Linux → Mac | Sanitized `PASS M1-RESULT` from `--role linux` | PASS / BLOCKED |
| UI diagnostic text | Literal `last probe: reachable`; color ignored | PASS / BLOCKED |

Any missing acknowledgement or signer, unavailable role, mismatched Dev boundary, non-Tailnet
target, non-Ready engine, negative diagnostic result, or missing reciprocal
report is **BLOCKED**, never a reduced PASS.
