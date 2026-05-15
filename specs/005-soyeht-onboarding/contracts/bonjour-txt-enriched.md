# Contract: Bonjour TXT Enriched (`_soyeht-household._tcp.`)

Per spec FR-012 and FR-013.

## Purpose

Add metadata fields to existing `_soyeht-household._tcp.` Bonjour service so app clients can render rich auto-discovery prompts ("Encontramos 'Sample Home' nesta rede — Adicionar este Mac?") without round-tripping HTTP. Backward-compatible: additive keys only, existing clients ignore unknown.

## Scope

This contract describes the **enriched** TXT shape for `_soyeht-household._tcp.`. The new `_soyeht-setup._tcp.` service has its own contract in `setup-invitation.md`.

## TXT shape (enriched)

The complete TXT record for `_soyeht-household._tcp.` after this enrichment:

| Key | Type | Phase | Description |
|-----|------|-------|-------------|
| `v` | uint | 2/3 | Always `1`. Existing. |
| `hh_id` | tstr | 2/3 | Household ID `hh_<base32>`. Existing. |
| `pairingState` | tstr | 2/3 | `device` (Phase 2 owner-pairing window open) / `open` (legacy, deprecated) / `none` (no pairing window) / `joiner` (Phase 3 candidate). Existing. |
| `m_id` | tstr | 2/3 | This machine's ID `m_<base32>`. Existing. |
| `version` | tstr | 2/3 | Engine version e.g. "0.1.10". Existing. |
| `host_label` | tstr | **NEW** | Human-readable machine model: "MacBook Pro", "Linux mini", etc. Best-effort. Empty if undetectable. UTF-8, ≤32 bytes. |
| `hh_name` | tstr | **NEW** | Casa display name (user-supplied via `/bootstrap/initialize`). UTF-8, 1..=64 bytes. **NOT** present in Phase 2/3 — purely informational; clients SHOULD NOT rely on it for trust decisions. |
| `owner_display_name` | tstr | **NEW** | Owner first name from iCloud (if available) or empty. UTF-8, ≤32 bytes. |
| `device_count` | uint | **NEW** | Number of personal devices paired (1+ in `ready` state, 0 in `named_awaiting_pair`). |
| `platform` | tstr | **NEW** | `macos` or `linux`. |
| `bootstrap_state` | tstr | **NEW** | Engine state machine state: `named_awaiting_pair` / `ready` / `recovering`. (Engines in `uninitialized` / `ready_for_naming` don't publish this service — they publish `_soyeht-setup._tcp.` instead.) |

Existing Phase 2/3 keys (e.g., `pair_device_window_*`, `pair_machine_window_*`) preserved unchanged.

## TXT total size

Bonjour TXT records have a 1300-byte limit (RFC 6762 §6.1). Worst-case estimate of new fields:

- `host_label` (≤32) + `hh_name` (≤64) + `owner_display_name` (≤32) + `device_count` (≤4) + `platform` (≤6) + `bootstrap_state` (≤22) = ~160 bytes added.

Existing TXT for Phase 2/3 hovers around 400-500 bytes. After enrichment: ~560-660 bytes. Well within limit.

## Encoding

Per existing protocol:
- All keys are ASCII.
- Values UTF-8 encoded.
- Each key=value pair is one TXT record entry (`<key>=<value>`).
- Pair length per entry ≤255 bytes.
- Bools encoded as `"true"`/`"false"` strings.
- uints encoded as decimal text strings.

## Backward compatibility

### Phase 2/3 clients in field

Existing clients (older iSoyehtTerm versions, brew-installed daemons) use known parsers that iterate keys defensively. Unknown keys are silently ignored.

Behavior:
- Old client sees enriched TXT → uses fields it knows (`hh_id`, `pairingState`, etc.); ignores `hh_name` and friends. **No regression**.
- New client sees old (un-enriched) TXT → handles missing keys gracefully (FR-016: nil → fallback "Casa de \(host_label)" or generic "Casa"); the enriched UX gracefully degrades.

### Migration path

No migration step required. As engines upgrade to the new version, they start emitting enriched TXT automatically. Old engines continue emitting old TXT until upgraded.

## App-side rendering

When SoyehtMac/Soyeht iPhone discovers a household via `_soyeht-household._tcp.`:

```
"<hh_name> · <device_count> device(s)"
"<platform>: <host_label>"
"Versão <version>"
```

Example:
```
"Sample Home · 2 devices"
"macOS: MacBook Pro"
"Versão 0.1.10"
```

If `hh_name` is empty (legacy engine), fall back to `"Casa de <host_label>"`.

## Validation

- Engine validates `hh_name`, `host_label`, `owner_display_name` for length and UTF-8 validity before emitting.
- Forbidden chars (control bytes < 0x20 except space) are stripped at publish time.
- App clients re-validate on receipt; reject TXT with malformed UTF-8 or oversized fields (defense in depth).

## Tests

- Contract: TXT byte size with worst-case fields.
- Contract: TXT key list parity between Rust publisher and Swift `NWBrowser` consumer.
- Integration: forward-compat — old client (Phase 2 era simulator) parsing enriched TXT works without crash.
- Integration: backward-compat — new client (Soyeht iOS post-spec) parsing un-enriched TXT renders fallback strings.
- Regression test extending `bonjour_macos_smoke.rs` (PR #42 base) to assert enriched keys present on macOS multi-interface publishers.
