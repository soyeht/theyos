# Owner-mesh rendezvous — canonical wire encoding (v1)

**Correction (2026-07-21, in-place — supersedes raw-SHA-256 `3c3c45ab…`).** §3's
printed key-sets were corrected from alphabetical to the actual canonical
`household_rs::cbor` (RFC 8949 §4.2.1) **length-first** byte order — the encoder's
true output, not a hand-sorted list. §1 (profile), §6/§8 (budgets), §7 (`err.*`
taxonomy), and the R0b companion (`9bd608fb`) are **unchanged**; only §3's
illustrative order (and this note) changed. The prior frozen bytes (`3c3c45ab`)
are superseded history.

Author: jovian · 2026-07-21 · Verification: verifier ≠ author — @safia re-GO
(wire security + budget trio + R0b anchor preservation) + @adriana re-ok (B6:
each err.\* observable and distinct) **before any freeze**. Merge: @kiana.
Data-only; no `admin/rust`, `household-rs`, corpus, consumer, fixture, guard,
reseal, or posture change.

## 0. Role, anchor, and non-changes

This document pins **only the byte-level wire encoding** of the message shapes,
`err.*` taxonomy, cardinalities, and the rendezvous resource budgets — all
concretizing the reviewed R0b design (raw SHA-256
`9bd608fb4b2687df4d008236049920cf3aa0486c3b67216d4b57f30d089ef87b`,
byte-identical companion at
`docs/owner-mesh-rendezvous/r0b-protocol-contract-v1.1-final.md`, unchanged by
this document). It introduces **no new design, threat model, or posture**: the
three resource budgets in §8 are @safia's I3 anti-amplification concretizations
(same class as `MAX_CANDIDATES_PER_FRAME`), not new decisions.

**No failure frame (R0b §2/§7, decision D-A).** Nothing here adds a wire frame
for failure. Every `err.*` is a **local** classification (client parser, or
server-side state); on any failure the server emits nothing and the
`rendezvous_id` expires by TTL. This preserves the R0b uniform-silence wire that
closes the content **and** timing oracle.

This is synthetic-protocol design material only. It grants no production
authority and installs no provider, route, dial, or datapath.

## 1. Canonical-CBOR profile (deterministic)

The profile is **exactly** `household_rs::cbor::to_canonical_vec` /
`from_canonical_slice` (`admin/rust/household-rs/src/cbor.rs`) — the **same**
profile A2/DP use via `owner_site_ake.rs` `encode_canonical`/`decode_canonical`
and the DP corpus `format.canonical_cbor`. It is **RFC 8949 §4.2.1 deterministic
encoding**:

- definite-length encoding only (no indefinite-length items);
- integers and lengths in shortest form;
- every map's keys sorted by the **bytewise lexicographic order of each key's
  own canonical-CBOR encoding** (via `ciborium::value::Value` recursive
  canonicalization);
- no floating-point, no tags in this protocol's frames.

**Canonicity check (R0b §2 step 3):** a frame is canonical iff
`to_canonical_vec(from_canonical_slice(bytes)) == bytes`. Any decodable frame
whose bytes differ from that re-encoding is rejected `err.noncanonical_cbor`
before any field is interpreted.

**Byte fields:** every protocol byte field is a CBOR `bstr` (major type 2). In
the future JSON corpus a `bstr` is written as lowercase, even-length hexadecimal
without a `0x` prefix (DP `format.byte_strings`). No field is ever a text
representation of bytes.

## 2. Envelope — present in every frame

Every frame is a **single canonical-CBOR map** carrying the envelope keys plus
its kind-specific body keys in one flat map (keys sorted per §1). The envelope
mirrors the DP `record_layout` discipline (`domain`, `version`, integer `kind`):

| key | CBOR type | value | R0b precedence step |
|---|---|---|---|
| `domain` | tstr | fixed `"soyeht/owner-mesh/rendezvous/v1"` | §2 step 4 → `err.wrong_domain` |
| `version` | uint | exact `1` (no down-negotiation, D-B) | §2 step 5 → `err.version_unsupported` |
| `kind` | uint | frame code (§3) | §2 step 6 → `err.unknown_frame` |

No key is optional or silently absent; any key outside a frame's fixed key-set
is `err.unknown_field` (§2 step 8); wrong cardinality/type of a present field is
`err.wrong_shape` (§2 step 7).

## 3. Frame key-sets (kind codes + body)

Integer `kind` codes (DP uses integer kinds, e.g. `close=4`). Directions are
informational (R0b §2), not a wire key.

| kind | code | direction | body keys (besides envelope) |
|---|---|---|---|
| Hello | `1` | Device-D or Claw-M → server | `rendezvous_id` (bstr, §5), `candidates` (array ≤8, §4/§6) |
| Peer | `2` | server → Device-D or Claw-M | `rendezvous_id` (bstr), `peer_candidates` (array ≤8, §4/§6), `observed_reflexive` (candidate-of-class-reflexive, §4-b) |
| Ok | `3` | server → Device-D or Claw-M | `rendezvous_id` (bstr) |
| Close | `4` | bound participant → server | `rendezvous_id` (bstr) |

- `Ok` (kind 3) is the **only** terminal-path output frame (R0b §2/§7, D-A);
  there is no failure frame.
- `Close` (kind 4) authorization is the **bound transport session** (R0b §1),
  not a field: a `Close` arriving outside the ≤2 bound sessions is
  `err.close_unauthorized` (behavioral, §7).
- Absent by design (I5 — a present one is `err.unknown_frame` at step 6): any
  relay/mode/priority frame such as `RzUseRelay`.

The full canonical key-set per frame — **the byte order the §1 encoder
(`household_rs::cbor`) actually produces, not a hand-sorted list.** §1 sorts map
keys by their encoded-key bytes (RFC 8949 §4.2.1), so for these text-string keys
the **shorter key sorts first** (the `0x60+len` length header byte dominates the
comparison), then lexicographically within an equal length — this is **not**
alphabetical order. **§1 / the encoder is the sole authority for ordering; the
list below is its derived output, never hand-sorted**; a corpus frame in any
other key order is rejected `err.noncanonical_cbor` (§7.1 #4):
- Hello: `{kind, domain, version, candidates, rendezvous_id}`
- Peer: `{kind, domain, version, rendezvous_id, peer_candidates, observed_reflexive}`
- Ok / Close: `{kind, domain, version, rendezvous_id}`

## 4. Candidate sub-structure (I4 — exactly three classes)

Each element of `candidates`/`peer_candidates`/`observed_reflexive` is a
canonical-CBOR map with an integer `class` and class-specific keys. Its map-key
order, like every map, is the §1 encoder's (length-first) output — **not** the
field order described below, which is for reading only. Any other
class or extra key is rejected at the border — codec-level extra key is
`err.unknown_field`; a well-formed-but-disallowed class is the **behavioral**
`err.candidate_class_denied` (§7). The three classes (R0b §3):

| class | code | keys | source of authority |
|---|---|---|---|
| LAN / RFC1918 | `0` | `ip` (bstr, 4 or 16 bytes network order), `port` (uint 1..=65535) | none — hint only, unverified (R0b §3, SSRF-LAN residue) |
| reflexive (own session) | `1` | `ip` (bstr, 4 or 16 bytes), `port` (uint) | server-observed source of **this** session only (I4-b) |
| relay (signed offer) | `2` | `relay_endpoint` (map `{ip,port}` as above), `signed_offer` (**opaque bstr, len ≤ `N`**, §8-2) | roster-signed offer, P-256 PoP (I6) |

- `ip` is a `bstr` of exactly 4 (IPv4) or 16 (IPv6) bytes in network byte order;
  a wrong length is `err.wrong_shape`. Example fixtures use RFC 5737
  (`192.0.2.0/24`) and RFC 3849 (`2001:db8::/32`) only — never a real address.
- Class `2` `signed_offer` is an **opaque `bstr`** carrying the exact
  roster-signed bytes (the rendezvous never re-canonicalizes signed content, so
  the P-256 PoP binding survives on-wire — I6). The rendezvous **does not parse
  the offer interior**; it enforces one wire-shape check at the border:
  `len(signed_offer) ≤ N` (§8-2), else `err.signed_offer_too_large` (§7.1).
  Semantic verification of the offer is downstream at the dial gate, untouched.
- Relay class-2 candidates are additionally sub-capped at `K` per frame (§6/§8-3).

## 5. `rendezvous_id` encoding

`rendezvous_id` is a CBOR `bstr` of a **fixed 16 bytes (128 bits)** (@safia
ruling §8-1 — held at 16, not widened). It meets the R0b §1 `≥128 bits` CSPRNG,
single-use, TTL 20 s, non-linkable requirement. The encoding is a **flat opaque
byte string with no internal structure**: it does not encode, and cannot be
decomposed into, an epoch, counter, identity, `ClawVpnMobileClawId`,
`household_id`, or `baseMeshPublicKeyHex` (R0b §1/R0a). A wrong byte length is
`err.wrong_shape`.

## 6. Cardinalities (I3 — numeric budgets)

Wire-level budgets the corpus freezes (client-applied caps on server-supplied
data stay behavioral, R0b §4 R3). All are fixed, non-negotiable, non-configurable
protocol constants (D3):

- `candidates` / `peer_candidates` array length **≤ 8** (`MAX_CANDIDATES_PER_FRAME`,
  R0b §4 D-C). Exceeding is `err.frame_too_large` — a **count** guard at parse,
  **distinct** from `err.oversized_frame` (whole-frame raw bytes) and from
  `err.signed_offer_too_large` (one field's bytes). Three guards, three `err.*` (B6).
- **Relay class-2 sub-cap `K` = 2** per frame (§8-3): at most 2 of the ≤8
  candidates may be class-2 (relay). Relay is the I5 fallback; a peer never needs
  8 signed offers. Keeps the frame tight against the largest candidate.
- **`signed_offer` length ≤ `N` = 1024 bytes** (§8-2), enforced at the border.
- **`MAX_FRAME_BYTES` = 3072 bytes** (§8-3): whole-frame raw-byte ceiling; a
  larger frame is `err.oversized_frame` (step 1, before decode).
- `MAX_M1_PER_SESSION` = 8, `MAX_ATTEMPTS_PER_CANDIDATE` = 3,
  `MAX_CANDIDATES_PER_SESSION` = 8 are **session-state** budgets (behavioral,
  not a single-frame byte-vector) — surfaced as `err.budget_exhausted` (§7).

## 7. `err.*` taxonomy — byte-vector vs behavioral-only (B6)

Two disjoint kinds. **No `err.*` is a wire frame** (D-A); the labels are the
local rejection taxonomy the future corpus and the client parser share.

### 7.1 Byte-vector `err.*` (codec/parser — the corpus freezes an adversarial frame per row; 11)

Evaluated in the R0b §2 precedence chain (first failing check wins):

| # | attack (byte-vector) | `err.*` | distinct-from note |
|---|---|---|---|
| 1 | frame over `MAX_FRAME_BYTES` **raw bytes** (before decode) | `err.oversized_frame` | whole-frame bytes, **not** count (#10), **not** one field (#11) |
| 2 | not CBOR from the first byte (invalid major type) | `err.malformed_cbor` | not-CBOR, **not** EOF (#3) |
| 3 | CBOR truncated / EOF mid-item | `err.truncated_frame` | EOF, **not** malformed (#2) / noncanonical (#4) |
| 4 | valid CBOR, re-encode ≠ bytes (not shortest / unsorted keys) | `err.noncanonical_cbor` | valid-non-minimal, **not** malformed (#2) |
| 5 | wrong `domain` | `err.wrong_domain` | — |
| 6 | wrong `version` (no downgrade, D-B) | `err.version_unsupported` | — |
| 7 | unknown `kind` (incl. forged mode/relay frame, I5) | `err.unknown_frame` | — |
| 8 | wrong cardinality/type of a present field | `err.wrong_shape` | — |
| 9 | unknown/extra map key (no silent optional) | `err.unknown_field` | — |
| 10 | `candidates` count over 8 (§6) | `err.frame_too_large` | **count**, not bytes (#1) / one field (#11) |
| 11 | a candidate's `signed_offer` bstr length over `N` (§8-2) | `err.signed_offer_too_large` | **one field's bytes**, opaque (offer not parsed); not whole-frame (#1) / count (#10) |

Precedence (bytes → decode → canonical → domain → version → kind → shape →
field → count/field-size) makes any multi-violation frame deterministic: e.g.
malformed + oversized → `err.oversized_frame` (step 1 < 2); wrong version +
unknown kind → `err.version_unsupported` (step 6 < 7). `err.oversized_frame`
(whole frame > 3072) fires before decode; `err.signed_offer_too_large` (one
`signed_offer` > 1024 inside an otherwise ≤3072 frame) fires during shape parse.

### 7.2 Behavioral-only `err.*` (server/client state — NOT byte-frozen)

The frame is byte-valid; rejection depends on state, so the corpus does **not**
freeze a byte-vector for these:

| condition | `err.*` | distinct-from note |
|---|---|---|
| candidate of a disallowed class (incl. forged public endpoint) | `err.candidate_class_denied` | policy, one rule (R0b §7 note A) |
| `rendezvous_id` already consumed | `err.rendezvous_id_consumed` | consumed, **not** never-emitted |
| `rendezvous_id` never emitted | `err.unknown_rendezvous_id` | never-emitted, **not** consumed |
| `Close`/teardown from a non-bound session | `err.close_unauthorized` | teardown-authz, **not** slots-full |
| 3rd `Hello` on an id whose ≤2 pairing slots are bound | `err.pairing_full` | slots-full, **not** teardown-authz |
| session budget exhausted (§6) | `err.budget_exhausted` | — |
| revoke / `(authz_epoch,roster_digest)` change mid-session | `err.authority_revoked` | — |
| valid-class candidate whose end-to-end A2 fails | `err.a2_handshake_failed` | **cross-layer** — born in the A2 (owner-site DP) corpus, **never** frozen here (R0b §7 note B) |

`err.close_unauthorized` ≠ `err.pairing_full`: the former is an unauthorized
**teardown** (a valid `Close` from the wrong session); the latter is a **join**
when the two pairing slots are already taken. Both are behavioral (need
bound-session state); on the wire both are uniform silence (D-A).

## 8. Resource budgets — @safia's I3 ruling (concretization, not new posture)

@safia classified all three budgets below as concretizations of her existing I3
anti-amplification budget (R0b §4; same class as `MAX_CANDIDATES_PER_FRAME`),
**not new posture and not a Caio escalation**. Each is a fixed, non-negotiable,
non-configurable-larger protocol constant (D3 — non-disableable limits). They
live **only in this rendezvous wire**; they do **not** touch the merged
claw-share offer contract (`household-rs`), which is left unchanged.

### 8-1. `rendezvous_id` = fixed 16 bytes (128 bits) — @safia GO
Held at 16 bytes (not widened to 256): sufficient for a single-use, TTL-20 s,
non-linkable id; flat opaque `bstr`, no internal structure (§5). Wrong length →
`err.wrong_shape`.

### 8-2. `signed_offer` = opaque `bstr`, border-capped at `N` = 1024 bytes
The rendezvous treats `signed_offer` as an **opaque `bstr`** and never
deserializes the offer interior (semantic verification is downstream at the dial
gate, untouched). At the border, **before interpreting**, the parser checks
`len(signed_offer) ≤ N`; a longer value is rejected locally as
`err.signed_offer_too_large` (§7.1). Because the check is on the opaque bstr
length, it **covers any internal content, including the `Group` audience
variant**, without any semantic cap on the offer's fields.

`N` is **not** a maximum of the claw-share offer contract, and this document adds
**no** cap to that contract. It is a rendezvous-imposed I3 budget anchored in a
**representative** offer, not a measured maximum.

**Why the cap is on the opaque blob, not a sum of internal fields (fact, verified
at the object).** The `RelayStreamOfferContract` **type** permits unbounded text
on relevant contract and mint paths — the contract/mint API accepts free `String`
fields, so its serialized size is **not type-bounded**. Specific handlers may
bound specific fields (e.g. `member_id` is 54 chars in the group-offer handler
via `MemberDeviceBinding`), but the contractual type does not, and such bounds
are route-dependent and inconsistent. The **known** uncapped strings are
`claw_id`, `relay_endpoint`, and — when `audience = Group`, in which case they
enter the signed bytes — `group_id` and `member_id`; `rendezvous_token` is
bounded (≤ 128, `RendezvousToken::try_new`) and `kind` is pinned to a constant by
`validate()`. This set is **known, not exhaustive** — another uncapped field
could exist or be added. Reasoning about *which* fields are capped in *which*
routes is a losing game; the only robust bound is on the **opaque `bstr` length
at the rendezvous border**, agnostic to the offer's internal structure and to any
route-dependent field caps. `N` bounds the **entire opaque blob**: if another
uncapped field ever appears, the border cap still bounds the frame and no factual
claim here breaks. Internal field bounds are the claw-share contract's concern
(Product-A-adjacent), not the rendezvous's; this document adds **no** cap to that
contract.

**Derivation of `N` (fixed measurable fields + proposed string bounds + margin).**
Canonical-CBOR size of a representative `RelayStreamOfferContract` (`Group` offer
— the largest variant; serde field-name string keys; CBOR headers included):

| component | bytes |
|---|---|
| crypto: `guest_device_pub` 33 + `claw_static_pub` 32 + `signer_pub` 33 + `signature` 64 (+bstr headers) | ~170 |
| `rendezvous_token` ≤ 128 (+hdr) | ~130 |
| `slot_id` 16 + scalars/enums (`v`, `not_after`, `resource`, `expected_path`) | ~65 |
| `kind` fixed `"claw-share/relay-stream-offer"` | ~31 |
| representative free-text at assumed **B = 64** bytes each — `claw_id`, `relay_endpoint`, `group_id`, `member_id` (a `Group` offer, the largest) | ~264 |
| CBOR map keys (serde field names) + nesting overhead | ~180 |
| **representative total** | **~830** |

`B = 64` is only the **rendezvous's size assumption** about a reasonable offer,
used to dimension the opaque-blob cap (for @safia's ratification) — **never** a
claim about, or a cap on, the claw-share contract (which stays uncapped;
§8-2 above). Rounded up with anti-amplification margin: **`N = 1024` bytes
(1 KiB)** (holds the ~830 representative with ~190 B margin). A tighter assumed
`B` would shrink `N`.

**Honest functional bound (documented, accepted).** An offer whose
`claw_id`/`relay_endpoint`/`group_id`/`member_id` are so long that the serialized
contract exceeds `N` **cannot be carried as a rendezvous relay candidate** — the
rendezvous imposes its own frame discipline on what it relays. Normal offers fit.

### 8-3. Relay sub-cap `K` = 2 and `MAX_FRAME_BYTES` = 3072 bytes — derived trio
- **`K = 2`**: at most 2 class-2 (relay) candidates per frame (total still ≤ 8,
  §6). Relay is the I5 fallback; a peer never needs 8 signed offers.
- **`MAX_FRAME_BYTES` (worst valid frame — the larger `RzPeer`)** =
  `envelope + rendezvous_id + peer_candidates[8] (K=2 relay at N + 6 cheap) +
  observed_reflexive + CBOR overhead`:

  | component | bytes |
  |---|---|
  | envelope (`domain` 31 + `version` + `kind` + keys) + `rendezvous_id` (16) | ~87 |
  | 6 cheap candidates (`class` + `ip` ≤16 + `port`) at ~38 each | ~228 |
  | 2 relay candidates at `~64 + N` each = `128 + 2N` | 128 + 2·1024 = 2176 |
  | `observed_reflexive` (1 cheap) + `peer_candidates` array/keys + overhead | ~85 |
  | **worst-frame total** = `528 + 2N` | **~2576** |

  Rounded up with anti-amplification margin: **`MAX_FRAME_BYTES = 3072` bytes
  (3 KiB)** (holds the ~2576 worst frame with ~500 B margin; kept tight).

**Trio closes:** worst frame (`528 + 2N` = 2576) ≤ `MAX_FRAME_BYTES` (3072). ✓
`N` (1024) is generous for a real offer (~830, no legit rejection) and the frame
stays tight. @safia re-GOs both sides; @adriana re-oks the three distinct
size/count errors (§7.1 #1/#10/#11).

### 8-4. Three orthogonal size/count rejections (B6)
- `err.oversized_frame` — **whole frame** raw bytes > `MAX_FRAME_BYTES` (3072),
  step 1, before decode. Byte-vector: a frame of **3073** bytes.
- `err.signed_offer_too_large` — a candidate's **`signed_offer` bstr** length >
  `N` (1024), field-shape at parse, offer stays opaque. Byte-vector: a frame ≤
  3072 with one relay candidate whose `signed_offer` is **1025** bytes.
- `err.frame_too_large` — **candidate count** > 8. Byte-vector: 9 candidates.

Three orthogonal guards (whole-frame bytes ≠ one-field bytes ≠ count), three
`err.*`; on the wire all are D-A uniform silence.

## 9. Freeze and downstream (gate)

- **Not frozen by this PR.** At the final PR head, the raw triple
  (path + commit SHA + this file's raw SHA-256) is provided for **@safia re-GO**
  (§8 budget trio closes + N grounded in the fixed fields and ratified string
  bounds + companion `9bd608fb` byte-preservation) and **@adriana re-ok**
  (§7 each `err.*` observable and distinct, B6, incl. the three orthogonal
  size/count guards). Only after both is this complement frozen by raw SHA-256.
- **Then** (a separate authorized slice, not here) the synthetic rendezvous
  corpus is authored **against the frozen complement**: one data-only JSON in
  `admin/contracts/mobile-claw-vpn/v1/` (DP §9 pattern), a byte-vector per §7.1
  row, no in-repo consumer or guard; its strength is the SHA-bound byte-GO plus
  independent Rust/iOS recomputation.
- This complement changes no R0b design and does not touch `household-rs`; the
  companion's SHA remains `9bd608fb`.
