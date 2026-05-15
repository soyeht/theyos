# Contract: `POST /pair-machine/local/anchor` — owner-iPhone trust-anchor delivery

Per protocol §11/§12 (introduced 2026-05-07 to fix B7 from PR #28 round 3).

## Why this exists

Before this contract, `POST /pair-machine/local/finalize` accepted any
`JoinResponse` whose internal signature chain self-verified
(`response_sig` → `founder_cert.signed_under(hh_priv)` →
`hh_pub` reported in the same body). An attacker who can reach the
candidate's pre-household listener can mint their **own** household
root, sign a `founder_cert` for the candidate's `m_pub`, encrypt a
shard for `m_pub` (publicly known via `local/seed`), sign the response
under their fake `hh_priv`, and POST to `local/finalize` — every
internal cross-check passes because the chain is entirely self-contained.
The candidate then commits with the attacker's `(hh_id, hh_pub)`.

The fix is to require an **external trust anchor** that pins
`(hh_id, hh_pub)` in the candidate's window before any `JoinResponse`
is accepted. The anchor is delivered by the owner's iPhone, which
already knows `(hh_id, hh_pub)` from Phase 2 owner pairing, after the
human owner has verified the BIP-39 fingerprint match between the
QR-scanned `m_pub` and the candidate's terminal.

The candidate trusts the anchor because the iPhone proves it scanned
the QR by presenting the `anchor_secret` minted into the QR at install
time. The `anchor_secret` is **never returned by `local/seed`** so it
is not learnable from the network — only from the QR.

## Wire shape

### Request

```text
POST /pair-machine/local/anchor HTTP/1.1
Host: <candidate-addr-from-QR>
Content-Type: application/cbor
Content-Length: …

LocalAnchor = {
  "v":             1,
  "anchor_secret": bstr(.size 32),       ; from QR
  "hh_id":         tstr,                  ; e.g. "hh_abc…"
  "hh_pub":        bstr(.size 33),        ; SEC1-compressed P-256
}
```

`LocalAnchor` is encoded as deterministic CBOR per RFC 8949 §4.2.1.
The map keys are listed lex-sorted above.

Earlier drafts of this contract carried `owner_p_cert: PersonCert`
"for log-line / debug only". It was dropped: the candidate has no
`hh_priv` to validate it against during anchor pinning, and the
`anchor_secret` is already the gate. Carrying an unverified
`PersonCert` on the wire was dead weight. Logging uses the pinned
`(hh_id, hh_pub)` directly.

### Success response (`200 OK`)

```text
HTTP/1.1 200 OK
Content-Type: application/cbor
Content-Length: …

LocalAnchorAck = {
  "v": 1,
}
```

### Failure response (`401 Unauthorized`)

Generic-CBOR `{v=1, error="unauthenticated"}` per R14 / FR-019a.

## Server-side validation (candidate M2)

Order of checks. **All** must pass before the anchor is pinned.

1. **State gate** — `pair_machine_window.state ∈ {Staging,
   AwaitingOwner}`. `Idle`, `Aborted`, or `Committed` → 401.
2. **Re-encode** — body decodes as `LocalAnchor` AND its canonical
   re-encoding is byte-equal to the request body. Otherwise 401.
3. **Anchor-secret match** — `body.anchor_secret` constant-time-equals
   `pair_machine_window.anchor_secret`. Otherwise 401. This is the
   transport-layer authenticator: the iPhone proves it scanned the
   QR. The same window may receive multiple identical anchor POSTs
   (idempotent retry); divergent anchors with the same secret are
   refused (see step 6).
4. **`hh_pub` shape** — `body.hh_pub` decodes as a valid SEC1 P-256
   compressed point. Otherwise 401.
5. **`hh_id` derivation** — `derive_household_id(body.hh_pub) ==
   body.hh_id`. Otherwise 401. (Defense in depth: the iPhone is
   honest about the binding it is pinning.)
6. **Idempotency / divergence** — if `pair_machine_window.pinned_hh_id`
   is already set:
   - Same `(hh_id, hh_pub)` as already pinned → return 200 (idempotent).
   - Different `(hh_id, hh_pub)` → 401, do NOT overwrite. The first
     anchor pinned wins; an attacker who somehow obtains the
     `anchor_secret` after a legitimate pin cannot displace it.

On all checks passing, persist
`pair_machine_window.pinned_hh_pub = body.hh_pub` and
`pair_machine_window.pinned_hh_id = body.hh_id` atomically with the
window snapshot, then return 200 with `LocalAnchorAck{v=1}`.

The persist call MUST mutate the in-memory pin and the on-disk
snapshot atomically: if the on-disk persist fails the in-memory pin
MUST be rolled back so an iPhone retry does not short-circuit
against an in-memory pin that never reached disk.

## Interaction with `local/finalize`

`POST /pair-machine/local/finalize` (per
`contracts/join-request.md`-derived JoinResponse handling) MUST add a
new pre-flight gate AFTER the existing CBOR shape / `join_request_hash`
checks and BEFORE any cert-chain verification:

- **Anchor-required gate** — if
  `pair_machine_window.pinned_hh_pub.is_none()`, return 401. The
  candidate refuses any `JoinResponse` until the iPhone has delivered
  the anchor.
- **Anchor-match gate** — `body.household_record.hh_pub ==
  pair_machine_window.pinned_hh_pub` AND `body.household_record.hh_id
  == pair_machine_window.pinned_hh_id`. Otherwise 401. This pins the
  founder cert chain to the household the human verified.

`founder_cert` is then verified against `pinned_hh_pub` (not against
the response's own `hh_pub`, which is now redundant). Every other
check in the existing finalize handler stays.

## Producer (Soyeht iPhone app)

After the human owner taps "Approve" with biometric, the iPhone
sequences the two POSTs **in order**:

1. POST `LocalAnchor` to **M2** at
   `POST <candidate-addr>/pair-machine/local/anchor` carrying the QR's
   `anchor_secret` and the household identity the iPhone already
   trusts from Phase 2 pairing (`hh_id`, `hh_pub` — only those two
   fields, plus the `anchor_secret`, reach the wire; see "Wire shape"
   above). The iPhone reaches `<candidate-addr>` over Tailscale
   (Story 1). **Wait for the `200 LocalAnchorAck` before proceeding
   to step 2.** This makes the candidate's pin a strict
   happens-before of the M1-driven 2PC and avoids the
   anchor-vs-approve race in which M1 would call `local/finalize`
   against an unpinned candidate window and abort a ceremony that is
   in fact valid.
2. POST `OwnerApproval` to **M1** at
   `POST /api/v1/household/owner-events/<cursor>/approve` (existing
   flow, drives the 2PC). At this point M2's window already has
   `pinned_hh_pub` / `pinned_hh_id` set, so M1's
   `finalize_with_m2` call will pass the anchor gates on M2.
3. If the anchor POST fails (network error, 401), the iPhone retries
   with exponential backoff for up to 30 s. Persistent failure
   surfaces as a "connection to new machine failed" error to the
   human, with a manual-retry option. The iPhone MUST NOT POST
   `OwnerApproval` to M1 while the anchor POST has not been ACKed —
   doing so corrupts a recoverable error into an aborted ceremony.

Story 2 (LAN/Bonjour) does not have a candidate-minted
`anchor_secret` (no QR), so the producer flow above does not apply.
Story 2's anchor mechanism is a Phase 5 design item (see
"Story 2 anchor mechanism" below).

## QR carries `anchor_secret`

The `soyeht://household/pair-machine` URI gains one new field per
`contracts/pair-machine-url.md`:

```
&anchor_secret=<base64url no-pad of 32 random bytes>
```

The candidate mints `anchor_secret` at install time alongside `nonce`
and persists it in the window snapshot. The two secrets serve
distinct purposes:

| Secret          | Purpose                                  | Exposed via                  |
| --------------- | ---------------------------------------- | ---------------------------- |
| `nonce`         | Bind candidate's signed `JoinChallenge`  | QR + `local/seed` JoinRequest |
| `anchor_secret` | Authenticate iPhone-side anchor delivery | QR only — never `local/seed` |

`anchor_secret` MUST NOT leak from any HTTP endpoint. The
`/pair-machine/local/seed` response carries the cached `JoinRequest`
CBOR (which embeds `nonce` but does not embed `anchor_secret`).
Logging or tracing MUST NOT record `anchor_secret` (only its
truncated hash if observability is needed).

## Security argument

- An attacker on the network who only sees `local/seed` learns
  `m_pub`, `nonce`, `challenge_sig`, `hostname`, `platform` but NOT
  `anchor_secret`. They cannot forge a valid `LocalAnchor`.
- An attacker who can call `local/finalize` (no auth) but cannot
  produce a valid `LocalAnchor` is blocked by the anchor-required
  gate.
- An attacker who acquires `anchor_secret` by physically photographing
  the QR has equivalent authority to the legitimate owner — at that
  point physical security is already compromised. The fingerprint
  comparison still requires the human owner to approve, which a
  remote attacker cannot do.
- Replay protection: the anchor is single-use per window
  (idempotency above). A new `theyos install --pair-machine`
  generates a fresh `anchor_secret`, invalidating any stale anchor.
- Forward secrecy: the `anchor_secret` is bound to the install-time
  window; once the window commits or aborts, the secret is no longer
  honored.

## Story 2 anchor mechanism (Phase 5 follow-up — out of scope here)

Story 2 (LAN auto-discovery via Bonjour, per `spec.md` US2 / tasks
T081–T092) admits a candidate that ran a vanilla `theyos install`
without `--pair-machine`, so the candidate does NOT mint an
`anchor_secret` and does NOT print a QR. The owner iPhone has no
QR-borne secret to present, and the candidate's `local/anchor`
handler — as specified above — refuses any pin without
`window.anchor_secret` (line "Window was opened by the founder-side
staging path…" in `handlers_pair_machine.rs`).

Implications for this PR (Phase 3 / Story 1):

- The `local_finalize_handler` anchor-required gate is enabled
  unconditionally.  Story 1 candidates (those that ran `theyos
  install --pair-machine`) mint `anchor_secret` and the iPhone POSTs
  the anchor before approve. Story 1 ceremonies pass the gate.
- Story 2 candidates (vanilla install + Bonjour) are NOT yet able
  to complete a join through `local/finalize` because the gate
  refuses an unpinned window. The Phase-5 work item is to design a
  Story 2 anchor mechanism that does not depend on a QR. Candidate
  designs (NOT decided in this PR):
  1. **Founder-mediated anchor**: M1, having authenticated the
     iPhone via existing Phase-2 owner-events, derives a per-window
     `anchor_secret` and forwards it through the iPhone to the
     Story 2 candidate over an out-of-band channel. The candidate's
     window snapshot needs a way to receive the secret (a new
     `local/seed-2` push handler keyed by Bonjour's TXT-record
     proof?).
  2. **Owner-cert chain anchor**: the iPhone's `OwnerApproval`
     carries the `(hh_id, hh_pub)` it intends to pin; M1's
     `finalize_with_m2` includes a fresh signed envelope binding
     them; the candidate validates the signature against the
     founder cert it learns from the response itself (recursive,
     so additional binding required to break self-reference).
  3. **Reclassify Story 2 as QR-required**: Bonjour discovery
     surfaces the candidate to M1 / iPhone, but the iPhone still
     requires the human to scan the QR rendered on the candidate
     terminal before approving. Simplest, but reduces the
     "no manual host arguments" property of Story 2 to "Bonjour
     for discovery, QR for trust".

Until Phase 5 picks one, Story 2 is feature-flagged off in the
Bonjour browser path: `theyos install` (vanilla) does not advertise
the `pair-machine` Bonjour service, and the Bonjour browser, on
detecting a Story-2-shaped announcement, MUST fail the ceremony
with a generic "this discovery flow is not yet wired up" error
rather than silently producing a 401-aborted ceremony. The
follow-up `T081`–`T092` tasks track the Phase 5 design and
implementation.

## Cross-repo coordination

`@agente-app` (iSoyehtTerm) MUST publish a matching contract under
`isoyehtterm:specs/003-machine-join/contracts/local-anchor.md`
so the iPhone client and the theyos candidate listener agree on:

- Wire CBOR field ordering (deterministic CBOR is already required).
- Retry / backoff schedule.
- Failure-surface UX strings.

The cross-repo gate (per `tasks.md` T099) MUST verify the two
contracts byte-equal where they overlap.
