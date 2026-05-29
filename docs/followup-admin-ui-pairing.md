# Follow-up: pair a device from the admin web panel (no CLI, no sudo)

The most Apple-grade path to pairing a phone with a server is **not** the
terminal — it is the admin web panel the operator is already told to open at
the end of install (`http://localhost:8892`). This follow-up tracks adding a
"Pair device" QR flow there so a fresh-start user never touches `soyeht pair`
or `sudo` at all.

Split out from [cli-secrets-permission-ux](followup-cli-secrets-permission-ux.md):
that work fixed the CLI/installer path (run pairing as the service account;
`soyeht pair` self-elevates interactively; `soyeht doctor` no longer false-FAILs
on EACCES). This item is the complementary, frontend-side product direction.

## Why this is viable today

- `POST /api/v1/mobile/pair-token` is `AdminUser`-gated
  (`admin/rust/server-rs/src/handlers_mobile.rs:927`, `handle_pair_token`). It
  accepts **any** authenticated admin — a logged-in session cookie works, not
  only the bootstrap token. So the panel (where the operator is already
  authenticated with the admin password printed at install) can mint a pairing
  token with **no on-disk secret read and no privilege escalation**.
- QR rendering infra already exists in the frontend
  (`admin/frontend/src/components/QrModal.tsx`) and a QR image endpoint exists
  server-side (`handle_pair_qr_image`, `/qr/{image_id}`).

## Scope (proposed, not yet designed)

- A "Pair device" / "Add iPhone" action in the panel that calls
  `POST /api/v1/mobile/pair-token` with the admin session, then shows the QR via
  `QrModal` + `/qr/{image_id}`.
- A TTL selector (the endpoint already takes `ttl_secs`; default 15 min, max 30
  days — mirror `soyeht pair`'s `parse_duration`).
- Single-use / expiry messaging consistent with the CLI copy.
- Decide placement: onboarding/first-run banner vs. a Devices/Settings page.

## What this deliberately avoids

- No new secret exposure, no group-readable token, no sudo, no CLI dependency
  for the common case. The CLI path remains for headless/SSH installs.

## Files of interest

- `admin/frontend/src/components/QrModal.tsx` — existing QR modal to reuse.
- `admin/frontend/src/**` — wherever onboarding / devices UI lives (entry point
  TBD during design).
- `admin/rust/server-rs/src/handlers_mobile.rs` — `handle_pair_token` (already
  admin-authed; likely no backend change needed) and `handle_pair_qr_image`.

## Status

Product direction, not scheduled. UI-strings must be English (lowercase
aesthetic, per project convention). No backend contract change anticipated.
