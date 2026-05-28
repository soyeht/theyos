# Follow-up: iOS should consume claw installability fields

**Status:** open — required for product quality, **not** a backend-compatibility
blocker. PR #88 ships the backend side; the iOS client work is tracked here.

## Symptom

Before PR #88 the Claw Store catalog advertised entries the backend would
reject at install time (e.g. `claude-claw`, a Claude Code plugin; Electron
desktop apps; ESP firmware). The iOS UI offered an Install button for claws
that can never install in a Firecracker VM, producing a confusing failure
after the user taps Install.

PR #88 fixes the **backend** contract so the client now has everything it
needs to gate the button up front. The iOS client must be updated to actually
use it.

## What PR #88 added (backend contract)

Two distinct shapes, both purely additive (a tolerant decoder ignores them):

1. **Catalog response** (`GET` claw catalog) exposes, at the **top level** of
   each entry:
   - `installable: bool` — always present.
   - `unavailable_reason_code: string` — snake_case enum
     (`"catalog_only"`, `"detected_unverified"`, `"no_install_plan"`); omitted
     when `installable == true`.
   - `unavailable_reason: string` — human-readable operator text; omitted when
     installable.

2. **Install error** (`POST` install, 400 Bad Request) uses the **existing
   error envelope**, so the reason is nested under `reasons`, not top-level:
   ```json
   {
     "error": "claw type 'claude-claw' is not installable yet: ...",
     "reasons": {
       "unavailable_reason_code": "catalog_only",
       "unavailable_reason": "Claude Code plugin, not a server daemon ..."
     }
   }
   ```
   Note the asymmetry: catalog → top-level `unavailable_reason_code`; install
   error → `reasons.unavailable_reason_code`. The legacy `error` field is
   preserved, so current clients do not break.

## What the iOS client should do

- Read `installable` from the catalog entry to **hide or disable** the Install
  button — do not duplicate tier/buildable/distribution logic client-side.
- Use `unavailable_reason_code` (the machine field) to select **localized
  copy** explaining why a claw is catalog-only / unverified. Do **not** parse
  `unavailable_reason`/`message` text for logic — it is display-only.
- If the client inspects install-error bodies, read the code from
  `reasons.unavailable_reason_code` (not top-level).

## Why a follow-up and not part of PR #88

The backend change is additive and non-breaking, so the current iOS build keeps
working (it just keeps showing the stale Install button). Closing the UX gap is
a separate client change in iSoyehtTerm.

## Files of interest (backend side)

- `admin/rust/claw-rs/src/store.rs` — `ClawCatalogResponse` fields.
- `admin/rust/core-rs/src/manifest.rs` — `ManifestEntry::installability`,
  `ClawInstallability`, `UnavailableReasonCode`.
- `admin/rust/server-rs/src/handlers_claws.rs`,
  `admin/rust/server-rs/src/handlers_mobile.rs` — install-error envelope.
