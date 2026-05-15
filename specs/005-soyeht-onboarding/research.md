# Phase 0 — Research: Soyeht Onboarding

Branch: `005-soyeht-onboarding` | Spec: [spec.md](./spec.md) | Plan: [plan.md](./plan.md)

This document resolves the 10 research items called out in `plan.md` § "Phase 0 — Research outputs". Each item has a Decision and a Rationale. No item is left as "TBD" or "we could go either way" — Constitution Principle V (closed plan) demands a decision.

## R1 — Engine residency on macOS: SMAppService (revised post-agente-front alignment)

**Decision**: Use **SMAppService** (modern macOS 13+ launchd registration) — NOT direct LaunchAgent plist drop. The plist content from the original R1 design (below) stays valid; only the **registration mechanism** changes.

**Architecture confirmation:** Engine is a **process separate** from Soyeht.app, spawned by `launchd`, NOT a child process of the app. Soyeht.app distributes the engine binary in `Contents/Helpers/soyeht-engine` and registers it via SMAppService at first launch. Engine has access to `Security.framework` normally as any macOS process, via `security-framework` Rust crate or direct FFI — no dependency on running inside the app's address space. Engine survives Soyeht.app being closed (mandatory per agente-front FR-002).

**Plist location:** Embedded in `Soyeht.app/Contents/Library/LaunchAgents/com.soyeht.engine.plist` (NOT dropped at install time to `~/Library/LaunchAgents/`). SMAppService reads it from inside the app bundle.

**Registration:** Swift app calls `SMAppService.agent(plistName: "com.soyeht.engine.plist").register()` on first launch. macOS surfaces a system notification: *"Soyeht wants to add a background item — Allow"*. User clicks once in System Settings → General → Login Items. Subsequent launches no prompt.

**Approval-required UX (delegated to agente-front):** Frontend agent's task `RequiresLoginItemsApprovalView` handles the case where `SMAppService.requiresApproval()` returns true — shows clear UX with deeplink to System Settings → Login Items. Agent-frontend FR coverage in iSoyehtTerm spec.

**Why SMAppService over plain `launchctl bootstrap`** (Apple-grade choice):
- Modern Apple-blessed path for macOS 13+ apps adding background items.
- User-visible in System Settings → Login Items (legitimate, easy to disable, no implicit autostart).
- One-time approval click is appropriate friction — system tells user *"Soyeht is asking permission"* — more honest UX than silent plist drop.
- Versioning: plist schema versioned via build phase script that updates `Contents/Library/LaunchAgents/com.soyeht.engine.plist` from a single source-of-truth template. Plist content authority = backend (this doc); embedding location authority = frontend (Swift build phase).

**Plist content (unchanged from original R1):**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" ...>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.soyeht.engine</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/<USER>/Library/Application Support/Soyeht/engine/soyeht-engine</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>EnvironmentVariables</key>
    <dict>
        <key>THEYOS_DIR</key>
        <string>/Users/<USER>/Library/Application Support/Soyeht</string>
        <key>THEYOS_HOUSEHOLD_PORT</key>
        <string>8091</string>
        <key>THEYOS_FORCE_SOFTWARE_KEYS</key>
        <string>1</string>
    </dict>
    <key>StandardOutPath</key>
    <string>/Users/<USER>/Library/Logs/Soyeht/engine.out.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/<USER>/Library/Logs/Soyeht/engine.err.log</string>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>WorkingDirectory</key>
    <string>/Users/<USER>/Library/Application Support/Soyeht</string>
</dict>
</plist>
```

Activation via `SMAppService.agent(plistName:).register()` from Swift on first launch. Replaces direct `launchctl bootstrap`.

**Rationale (plist content):**
- `KeepAlive.SuccessfulExit=false` keeps the engine alive on crash but doesn't restart on clean exit (e.g., Soyeht.app teardown — but engine should NOT exit cleanly during app teardown; only `bootstrap/teardown` triggers full stop).
- `ProcessType=Interactive` ensures the engine is suspended on user logout, restarted on login (no zombie engine in user-switching scenarios).
- Logs go to `~/Library/Logs/Soyeht/` so Console.app surfaces them naturally; not in `/var/log/` (would need sudo).
- `THEYOS_FORCE_SOFTWARE_KEYS=1` is mandated by Phase 3 carve-out (Shamir/ECDH needs raw scalar; Secure Enclave refuses to release P-256 private keys on macOS — see protocol §80).
- `<USER>` placeholder substitution happens at SMAppService registration time via Swift code (not shell expansion).

**Rejected alternatives (all considered, all rejected with rationale):**
- Direct `launchctl bootstrap` plist drop to `~/Library/LaunchAgents/`: rejected because SMAppService is the modern Apple-blessed API for macOS 13+ apps; bypassing it loses System Settings visibility and is less honest UX (silent install of background item).
- LaunchDaemon: requires sudo to install at `/Library/LaunchDaemons/`; breaks SC-004 (zero sudo).
- Per-app sandboxed XPC service: rejected because engine needs to bind unprivileged ports (8091/8892) globally accessible via Tailnet and LAN — XPC services are app-bound.

## R2 — Programmatic AirDrop API on iOS

**Decision**: Use `UIActivityViewController` with the `Soyeht.dmg` as a single `NSItemProvider` payload. Set `UIActivityType.airDrop` as the only excluded-otherwise activity type to keep the share sheet clean. iPhone publishes Bonjour beacon `_soyeht-setup._tcp.` BEFORE invoking the share sheet so the Mac, when it receives the AirDrop, can recognize "iPhone is waiting" via Bonjour discovery.

**Rationale**:
- `UIActivityViewController` is the only Apple-blessed API for AirDrop send. There is no programmatic "send file via AirDrop" private API; the user MUST tap the AirDrop entry in the share sheet.
- The share sheet auto-shows nearby devices on the same Apple ID; this is the most natural Mac-discovery UX.
- The Bonjour beacon decouples the file transfer from the post-install handshake: if AirDrop fails (different Apple ID, BT off), the user can manually visit `soyeht.com` and the Bonjour beacon still serves to skip the "name your casa" step on the Mac.

**Rejected alternatives**:
- `NSItemProvider` direct send (no public API — would be private SPI).
- Custom share sheet with AirDrop option only (rejected: indistinguishable from `UIActivityViewController` for the user, and rebuilding share UX is wasted work).
- Embed the .dmg URL in a deep link / Universal Link to `soyeht.com/install` and let the Mac browser fetch — rejected because requires the Mac browser to be open and the Universal Link to resolve, which is more steps than AirDrop.

## R3 — Sparkle integration

**Decision**: Sparkle 2.x with EdDSA signing (Sparkle 2.0+ supports modern signing key types). Appcast XML feed served at `https://soyeht.com/appcast.xml`. Bundle includes `sparkle-public-ed-key.pub` matched against private key held by release pipeline (PR #43 / PR #45 base). Sparkle update flow:

1. Sparkle compares running version to appcast latest entry on app launch (or every 24h, whichever first).
2. If newer version found, prompt user: "Soyeht 0.1.10 está disponível. Atualizar agora?"
3. User confirms → Sparkle downloads new Soyeht.dmg, verifies EdDSA signature, swaps in `/Applications/Soyeht.app`, relaunches.
4. On first launch of new app: SoyehtMac detects engine version mismatch (`/bootstrap/status.version` ≠ app's bundled version), re-extracts engine from `Contents/Helpers/` to `~/Library/Application Support/Soyeht/engine/`, restarts LaunchAgent.

**Rationale**:
- Sparkle is the de-facto standard for non-App-Store macOS apps (used by Transmission, Bartender, Linear, etc.).
- EdDSA signing (Ed25519) is faster than RSA/ECDSA at verification, smaller signatures, no parameter ambiguity. Note: this is signing the .app update, not Soyeht protocol (which uses P-256 per Constitution).
- Engine re-extraction on version mismatch is idempotent and atomic (temp file + rename).

**Rejected alternatives**:
- Custom updater (6+ months engineering on solved problem).
- App Store auto-update (rejected per "Cross-cutting decisions" in plan).

## R4 — Cross-compile Rust for Linux from macOS dev host

**Decision**: Use `cross` (https://github.com/cross-rs/cross) with Docker-based toolchains. Targets:
- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`

Build command in `make.sh`:
```sh
cross build --target x86_64-unknown-linux-gnu --release -p server-rs
cross build --target aarch64-unknown-linux-gnu --release -p server-rs
```

CI (GitHub Actions) builds both Linux targets + macOS target on every release tag, packages each into `dist/linux-{arch}/soyeht-engine-<version>.tar.gz`, signs with sha256, uploads to release.

**Rationale**:
- `cross` is mature, handles glibc version pinning (we target glibc 2.31 = Ubuntu 20.04 LTS minimum).
- Same workflow already proved with PR #43 (release-macos.yml). Extending to Linux targets adds 2 jobs to the matrix, ~4 minutes per build with cache.
- Avoids the `zig-cc` route which requires zig + extra build deps.

**Rejected alternatives**:
- `zig-cc` (rejected: extra dependency, less idiomatic Rust ecosystem).
- Native Linux runners on GitHub Actions (rejected: works but doubles secrets exposure surface; cross-compile keeps single Mac runner with secrets).

## R5 — Bonjour TXT enrichment backward compatibility

**Decision**: Add new TXT keys (`hh_name`, `owner_display_name`, `device_count`, `bootstrap_state`) as **additive only**. Existing keys (`hh_id`, `pairingState`, `m_id`, `version`, etc. — see protocol §13) preserved unchanged. Parsers MUST ignore unknown keys (already protocol behavior).

For Phase 2/3 clients in field that don't know about the new keys, behavior is unchanged: they see the same `hh_id` / `pairingState` / etc. and treat the rest as informational metadata.

**Rationale**:
- Bonjour TXT is structurally a key-value bag; adding keys is non-breaking.
- All existing iSoyehtTerm parsers in the wild already iterate keys defensively (they ignore unknown).
- Future-proofing: unknown keys silently ignored is the expected mDNS behavior across Apple's stack (`NWBrowser` itself does this).

**Edge cases**:
- TXT record total size limit is 1300 bytes (RFC 6762 §6.1). New keys are short (max ~50 bytes total addition); we're well under the limit.
- Owner display name is user-typed; sanitize to UTF-8 ≤ 64 bytes before publishing (matches existing hostname sanitization).

## R6 — Owner cert signing for teardown

**Decision**: Teardown POST body shape:

```cbor
TeardownRequest = {
  "v":          1,
  "op":         "teardown",                  ; constant string
  "hh_id":      tstr,                        ; "hh_<base32>"
  "m_id":       tstr,                        ; target machine id
  "nonce":      bstr(.size 32),              ; CSPRNG, single-use
  "ts":         uint,                        ; unix seconds, ≤ 5 min skew
  "signed_by":  P256Public,                  ; SEC1 33 bytes — owner device cert pubkey
  "signature":  bstr(.size 64),              ; r||s P-256 ECDSA over deterministic CBOR of all above except `signature`
}
```

iPhone Face ID gate: SoyehtCore exposes `OwnerCertSigner.signTeardown(...)` which prompts via `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` BEFORE pulling `D_priv` (device private key) from Secure Enclave to sign. If user cancels biometric, no signature is produced.

Engine-side validation order (in `handlers_bootstrap.rs::teardown_handler`):

1. CBOR re-encode → byte-equal check; otherwise 400.
2. `signed_by` is in the household's known device cert set (verified up to `hh_pub` via Phase 2 cert chain); otherwise 401.
3. ECDSA verify(`signature`, deterministic CBOR of body minus `signature`, `signed_by`); otherwise 401.
4. `nonce` not in recent-nonces cache (last 24h); otherwise 409 (replay).
5. `ts` within ±300 seconds of engine clock; otherwise 401 (clock skew / replay).
6. `m_id` matches engine's own `m_id`; otherwise 400 (cross-machine teardown attempt).

On all-pass, persist nonce, atomic-rm `household-state/`, transition to `uninitialized`, return 200 + empty body.

**Rationale**:
- Same shape as Phase 2/3 sign envelopes (consistency with existing protocol).
- `signed_by` carried in body to enable validation without external state lookup.
- Per Constitution II, this is a capability cert chain: `D_priv → device_cert → hh_priv → hh_pub`.

## R7 — systemd user unit + linger

**Decision**: Linux install script creates `~/.config/systemd/user/soyeht-engine.service`:

```ini
[Unit]
Description=Soyeht Engine
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%h/.local/share/Soyeht/engine/soyeht-engine
Environment=THEYOS_DIR=%h/.local/share/Soyeht
Environment=THEYOS_HOUSEHOLD_PORT=8091
Environment=XDG_DATA_HOME=%h/.local/share
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
```

Activation:
```sh
systemctl --user daemon-reload
systemctl --user enable --now soyeht-engine.service
```

Linger (engine survives logout) is **opt-in**. Install script asks: "Manter Soyeht ativo mesmo quando você não estiver logado? (recomendado para servidor 24/7) [s/N]". If "s", runs `sudo loginctl enable-linger $USER` — **the only sudo prompt in the Linux flow**, and user-controlled.

**Rationale**:
- systemd user units are well-supported on all target distros (Ubuntu 22.04+, Debian 12+, Fedora 38+, NixOS 24.05+).
- Default no-linger means engine runs while user is logged in (typical desktop Linux); user-server scenarios opt-in to linger.
- Single sudo prompt is acceptable trade-off for "server 24/7" capability — alternative (require linger always) breaks zero-sudo for desktop users.

**Rejected alternatives**:
- Always linger (rejected: forces sudo on every install).
- Cron @reboot (rejected: no socket-activation, no graceful restart, harder to manage).
- Foreground only (rejected: dies on terminal close, breaks "always-on casa" mental model).

## R8 — NixOS firewall fix

**Decision**: `nix/module.nix` updated:

```nix
networking.firewall = {
  enable = lib.mkDefault true;
  allowedTCPPorts = [ 80 443 22 cfg.port cfg.householdPort ];
  allowedUDPPorts = lib.optional cfg.tailscale.enable config.services.tailscale.port;
  trustedInterfaces = lib.optional cfg.tailscale.enable "tailscale0";
};
```

Where:
- `cfg.port` = admin panel port (default 8892)
- `cfg.householdPort` = household HTTP port (default 8091, **new option** — exposed in `module.nix` options block)

**Rationale**:
- Story 2 walkthrough hit ECONNREFUSED because :8091 was firewall-dropped on LAN (only `tailscale0` was trusted). With this fix, candidate-join works on LAN too.
- `cfg.householdPort` exposed for advanced users who want to bind elsewhere (rare).

## R9 — Engine binary size + bundle impact

**Decision**: Current `server` binary on macOS arm64 ≈ 28 MB unstripped, ≈ 18 MB stripped. Linux equivalent ≈ 32 MB / 22 MB. After UPX or `strip --strip-all`, both fit under ~25 MB.

Soyeht.app bundle delta from existing brew-distributed app: **+25-30 MB** for the engine in `Contents/Helpers/`. Total Soyeht.app size ≈ 80-100 MB. Sparkle download size acceptable (HTTP/2, modern compression). App Store iOS doesn't matter (the .dmg is not in iOS app); the iOS app bundles *no engine* (engine only on Mac/Linux servers).

Verify in Phase 1: extract engine to `~/Library/Application Support/Soyeht/engine/` as the `Contents/Helpers/` is read-only after notarization. Re-extract on Sparkle update.

**Rationale**:
- 25 MB is acceptable for an app that delivers a full self-host stack. For comparison, Tailscale macOS app is ~70 MB.
- Strip happens in CI (release pipeline) before notarization; debug symbols not shipped.

## R10 — iOS sandbox entitlements

**Decision**: Required entitlements (declared in iOS app `Info.plist` and `entitlements.plist`):

- `NSLocalNetworkUsageDescription` (string): "Soyeht usa sua rede local para encontrar suas máquinas (Mac, Linux) que rodam seus agentes."
- `NSBonjourServices` (array): `["_soyeht-household._tcp", "_soyeht-setup._tcp"]`
- `com.apple.security.network.client` = true (already present)
- `com.apple.security.network.server` = false (we don't need server; iOS app is client only)
- `NSCameraUsageDescription` (string): "Para escanear códigos de pareamento" (existing for QR fallback)
- `NSFaceIDUsageDescription` (string): "Para confirmar operações sensíveis como adicionar máquinas e apagar sua casa" (new — covers anchor-handoff confirm + teardown signing)

**Rejected alternatives**:
- `com.apple.developer.networking.networkextension` for AirDrop programmatic (rejected: unavailable to App Store apps without entitlement request to Apple; would gate v1 ship on Apple approval; `UIActivityViewController` is the supported path).

**App Review notes** (anticipating reviewer questions):
- The app needs Local Network because it discovers Soyeht-running machines via Bonjour on user's home/office network. This is core functionality; without it, the app cannot find user's own machines.
- The app uses Face ID for security-sensitive operations (adding machines to user's house, deleting house). User-facing description in `NSFaceIDUsageDescription` explains this in non-technical terms.
- The app does NOT collect data; user's house identity stays on their hardware. Privacy nutrition label: "Data Not Collected".

---

## R11 — APNs push delivery (added post-agente-front alignment)

**Decision**: **Shared bundled `.p8` provider key** in `Soyeht.app/Contents/Resources/apns.p8`, rotatable via Sparkle update. Apple Push delivery from engine direct to APNs gateway.

**Rationale**:
- Per-house provider keys (theoretically more isolated — each casa has its own APNs identity) are operationally complex: would require Apple Developer Program registration per casa OR a multi-team-id management layer over a shared developer account. Impractical for v1.
- APNs proxy via our infra (Cloudflare Worker) introduces a privacy concern: device tokens flow through us. Violates Constitution III spirit ("local-first").
- Shared bundled key is the pragmatic Apple-platform pattern (used by most non-trivial apps with push). Trade-off: Apple knows which devices have Soyeht (which they already know via App Store distribution); does NOT compromise per-casa privacy because the engine signs each push with the bundled key but the contents are casa-bounded.
- Rotation: `.p8` shipped in `Contents/Resources/apns.p8`; updated via Sparkle delta when key rotation needed. Engine reads on startup; no hot-reload (acceptable — push-key rotation is rare).

**Future migration path** (documented for v0.3.0+): per-house provider keys via App Store Connect API, requiring infrastructure investment in Apple Developer Program automation. Triggered when telemetry shows scale that justifies it OR audit shows we need stronger per-casa isolation.

**Authority split**:
- Backend (theyos): handles push token registration endpoint (`POST /push/register-device-token`), sends push via APNs gateway from engine, owns push-message-content contracts.
- Frontend (iSoyehtTerm): handles iOS APNs registration (UNUserNotificationCenter.requestAuthorization, registerForRemoteNotifications), forwards token to backend, handles received notifications. The `.p8` cert ships in `Soyeht.app/Contents/Resources/` (frontend build), but the cert content is provisioned by backend (Apple Developer Program account holder).

**Documented in `docs/household-protocol.md`** §Push Delivery.

## Summary

All 11 research items resolved with concrete decisions. No item left as TBD. No blocker for Phase 1 design.

Outstanding items going into Phase 1: write the contracts (6 markdown files), data-model.md (state machine + entities), quickstart.md (dev walkthrough). All inputs to those are now decided.
