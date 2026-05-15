# Contract: `GET /bootstrap/status`

Per spec FR-002.

## Purpose

Engine's machine-readable state report. The app cliente polls this during onboarding to know which UI to render. Replaces filesystem-state inference and brittle "is the daemon up?" checks.

## Wire shape

### Request

```
GET /bootstrap/status HTTP/1.1
Host: 127.0.0.1:8091
Accept: application/json
```

No auth required (loopback only by default; Tailnet-only in production via Tailscale ACL).

### Success response

```
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "v": 1,
  "state": "uninitialized" | "ready_for_naming" | "named_awaiting_pair" | "ready" | "recovering",
  "version": "0.1.10",
  "platform": "macos" | "linux",
  "host_label": "MacBook Pro",
  "uptime_secs": 4231,
  "hh_id": "hh_<base32>" | null,
  "device_count": 0
}
```

`hh_id` is `null` while in `uninitialized` or `ready_for_naming`; non-null in `named_awaiting_pair`, `ready`, `recovering`.

`device_count` is the number of paired personal devices (iPhones); zero in `named_awaiting_pair`, ≥1 in `ready`.

`host_label` is best-effort machine model detection; falls back to hostname if unavailable.

### Error responses

- **503 Service Unavailable** — engine is starting up but bootstrap-state listener isn't fully ready. Body: `{v:1, state:"starting"}`. Client SHOULD retry after 200 ms.

## Polling guidance

App cliente polls every **200 ms** during onboarding. Backs off to 5s once state is stable (`ready` reached). Stops polling when app foregrounds away from onboarding flow. WebSocket push intentionally not used (Constitution: simplest sufficient mechanism).

## Validation

No validation required of the response by client; field types are well-known and any unknown field MUST be ignored (forward compatibility).

## Backward compatibility

This is a new endpoint. Existing clients (older iSoyehtTerm versions, brew-installed daemons) won't expose it; SoyehtMac's auto-discover MUST handle 404 by falling back to the legacy "is /health responding?" probe and treating it as `ready` (since the old flow assumed `ready` after `brew install + soyeht start`).

After the brew flow is removed (Constitution IV), this fallback can be deleted in a subsequent change set.
