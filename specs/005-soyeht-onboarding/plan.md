# Implementation Plan: Soyeht Onboarding (Casa, primeiro Mac/Linux, paridade backend)

**Branch**: `005-soyeht-onboarding` | **Date**: 2026-05-09 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `specs/005-soyeht-onboarding/spec.md`

## Summary

Replace today's two-step install (`brew install theyos` + open SoyehtMac to talk to the daemon) with a single Apple-grade onboarding where the engine is bundled inside Soyeht.app on macOS and inside a single curl-script on Linux, the user never types sudo, never reads the words `household` / `daemon` / `theyOS`, and a fresh machine completes its first pair (Mac founder + iPhone) in under 60 seconds.

The technical approach is a re-architecture of the engine bootstrap as a **state machine driven by HTTP from the client app** (`uninitialized` → `ready_for_naming` → `named_awaiting_pair` → `ready`), bundled binary distribution (Soyeht.app/Contents/Helpers/soyeht-engine on Mac; user-space install at `~/.local/share/Soyeht/` on Linux with systemd-user unit), enriched Bonjour TXT for app-side auto-discovery, a new `_soyeht-setup._tcp.` Bonjour service for "iPhone-waiting-for-Mac" handshake (Caso B), and an `anchor-handoff` capability endpoint that lets owner-paired iPhones complete machine-join via the Tailnet trust path without any QR scan in the common case. The brew-based install path is removed in the same change set per Constitution Principle IV.

## Technical Context

**Language/Version**: Rust 1.85+ (engine, edition 2024 already in workspace) | Swift 5.10+ (SoyehtMac, Soyeht iOS — iOS 16+ / macOS 14+) | Bash 5+ (curl install script for Linux)
**Primary Dependencies**:
- *Engine*: existing workspace (`server-rs`, `household-rs`, `core-rs`, etc.); `mdns-sd` (Linux Bonjour publish) + `bindgen` FFI to `dns_sd.h` (macOS Bonjour, established in PR #42); `axum` for HTTP; `tokio`; `tracing`; `serde`/`ciborium` for CBOR
- *SoyehtMac*: SwiftUI + AppKit, `NWBrowser`/Network.framework (Bonjour), `Sparkle` (auto-update), `Foundation` URLSession (engine HTTP), `LaunchServices` for `launchctl` programmatic invocation
- *Soyeht iOS*: SwiftUI, `NWBrowser` (Bonjour over WiFi+Tailscale), `UIActivityViewController` (AirDrop), `LocalAuthentication` (Face ID/Touch ID), `CryptoKit.P256` (cert signing for teardown)
- *Linux install script*: pure POSIX sh, `curl`, `tar`, `sha256sum`; optional `systemctl --user`

**Storage**: Files only. State dir per-user (`~/Library/Application Support/Soyeht/` on macOS, `$XDG_DATA_HOME/Soyeht/` on Linux). Identity keys in Secure Enclave (macOS) or kernel keyring (Linux). No databases. Atomic file writes via existing `household-rs` persistence helpers.

**Testing**: `cargo test` at workspace level for engine (unit + contract + integration); `e2e-rs` crate for hardware walkthroughs (Caso A, Caso B, Linux founder, Linux candidate); XCTest for SoyehtMac; XCTest for iOS app; `bonjour_macos_smoke.rs` regression test (lesson learned from T046 publisher silence) extended to cover `_soyeht-setup._tcp.`

**Target Platform**:
- macOS 14+ (Sonoma) on Apple Silicon (M1+)
- Linux: kernel 5.x+ + systemd-based distros (Ubuntu 22.04+, Debian 12+, Fedora 38+, NixOS 24.05+) on x86_64 and ARM64; non-systemd distros and Termux are out of scope (per Clarifications session)
- iOS 16+ (iPhone 11 and newer)

**Project Type**: Cross-repo: `theyos` (Rust engine + curl install script + NixOS module) and `iSoyehtTerm` (SoyehtMac + Soyeht iOS, both Swift, sharing `SoyehtCore`).

**Performance Goals**:
- Caso A end-to-end (drag-to-Applications → "Sua casa está pronta"): < 60 seconds at p95
- Caso B (App Store tap → "Sua casa está pronta") with AirDrop: < 90 seconds at p95
- Linux candidate join (curl finish → iPhone sees "Linux entered casa"): < 30 seconds at p95
- Engine cold-start `/bootstrap/status` first response: < 200 ms
- Bonjour `_soyeht-setup._tcp.` discovery latency on Tailnet: < 3 seconds (95th percentile)
- 95% of pairings via Tailnet trust path (anchor-handoff, no visible QR)

**Constraints**:
- Zero sudo prompts in macOS flow (LaunchAgent; non-privileged ports; no system-wide install)
- Zero terminal commands in macOS flow (after the .dmg drag)
- Linux flow: maximum 1 terminal command (the single curl|sh)
- Engine binary bundled inside Soyeht.app — no separate brew install — `Soyeht.app` version locked-in-step with engine version (no version skew)
- iOS app constrained by App Store sandbox — entitlements already present (Bonjour, Local Network, NWBrowser); new entitlement for `com.apple.developer.networking.networkextension` may be needed for AirDrop programmatic, validated in Phase 0
- App Store review cycles for iOS (1-7 days each) constrain ship cadence
- Constitution V: closed plan — every alternative is decided here, none deferred
- Constitution IV: brew-based install path removed in same change set (no parallel old/new paths)

**Scale/Scope**:
- ~80% backend code shared between Mac and Linux engine builds (existing workspace already platform-portable)
- ~5 new HTTP endpoints in `server-rs` (`/bootstrap/status`, `/bootstrap/initialize`, `/bootstrap/teardown`, `/bootstrap/claim-setup-invitation`, `/pair-machine/anchor-handoff`)
- 1 new Bonjour service (`_soyeht-setup._tcp.`)
- ~5 new SwiftUI screens in SoyehtMac (Welcome refactor + chave-girando + cartão-da-casa + recovery-comm + onde-instalar)
- ~6 new SwiftUI screens in Soyeht iOS (carrossel 5 cards + onde-instalar + AirDrop progress + name-the-casa + adding-Linux confirm + recovery-comm)
- Estimated ~3000-5000 lines added across both repos (rough)
- Zero existing-user migration in this spec (greenfield only); migration spec deferred to 006

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-checked after Phase 1 design.*

| # | Principle | Status | Notes |
|---|-----------|--------|-------|
| I | Apple-Grade Quality (no SPOF, no manual ops, automatic discovery/failover, UX hides infrastructure) | **PASS** | Zero sudo, zero terminal Mac, single curl Linux, motor invisível em UI, auto-discovery via Bonjour Tailnet trust, anchor-handoff substitui QR scan na maioria dos casos, recuperação via Shamir entre membros. |
| II | Capability-Based Authorization (signed certs chain to household root; no RBAC; no bearer; UI from local cert) | **PASS** | `/bootstrap/teardown` autenticado por assinatura do device cert pessoal do owner (Phase 2 cert chain → hh_priv); `anchor-handoff` autenticado por Tailscale ACL como capability of-presence-on-tailnet (acceptable per spec); `claim-setup-invitation` autenticado por token efêmero (proof-of-possession do iPhone que iniciou). Sem bearer, sem RBAC. |
| III | Local-First Identity & State (no central cloud control plane; Bonjour + Tailscale only) | **PASS** | Identidade nasce no Mac/Linux do usuário (Secure Enclave / kernel keyring). Discovery 100% Bonjour/Tailscale. Telemetria endpoint é **opt-in user feature** (FR-032..036), não control plane — atende a "permitido para user-facing features que o usuário explicitamente opta", **com PII strip + enum fechado**. soyeht.com hosting do install script + .dmg distribution é "static asset CDN", não control plane. |
| IV | Adoption-First, No Legacy Compatibility (no parallel old/new code paths; phase ends end-to-end functional) | **PASS** | brew-based install path (`brew tap soyeht/tap && brew install theyos`) removido no mesmo change set; `theyos.rb` formula deprecated com aviso "veja soyeht.com pra nova instalação"; `install_cli.rs` (caminho `theyos install --pair-machine`) refactored — não removido, fica como path interno acionado pelo app. NixOS module legado coexiste por uma janela explícita (06-migration), não para esta spec. |
| V | Specification-Driven Development (closed plan, no open alternatives; English artifacts; spec exists before implementation) | **PASS** | Spec fechado (3 [NEEDS CLARIFICATION] resolvidos no clarify); plan fecha cada alternativa abaixo (ex: LaunchAgent NÃO LaunchDaemon, Sparkle NÃO custom updater, App Store NÃO TestFlight). Spec, plan, contracts em **English** (commit messages, code, contracts). User-facing UX strings em PT-BR + EN (i18n via `LocalizedStringResource`). |

**Engineering standards check:**

- [x] Apple APIs used precisely: `NWBrowser` not generic mDNS; `LocalAuthentication` not custom biometric; `kSecAttrTokenIDSecureEnclave` for `hh_priv`; `LaunchServices.OSAStatus` not shell out for `launchctl bootstrap` invocation
- [x] Cryptographic primitives match Engineering Standards: ECDSA P-256 for `hh_priv`, ECDH P-256 for shard agreements (Phase 3), BLAKE3-256 hashing, ChaCha20-Poly1305 AEAD, Shamir GF(256) for `hh_priv` custody. Identity-bearing keys in Secure Enclave (macOS) / kernel keyring (Linux).
- [x] No silent error swallowing at protocol boundaries: `try?` banido em validation paths; bootstrap state transitions return typed errors via `axum::extract::rejection::Rejection`; cert chain failures emit `tracing::warn!` and return 401 (no `try?` swallow)
- [x] Tests planned at protocol boundaries: contract tests for each endpoint shape (CBOR re-encode, signature verify, anchor-secret constant-time-equals); integration tests for state machine transitions; hardware walkthroughs for Caso A/B/Linux scenarios.

**Cross-cutting decisions made (no deferred alternatives):**

| Decision Point | Decision | Rejected Alternative |
|---|---|---|
| macOS engine residency | LaunchAgent per-user under `~/Library/LaunchAgents/com.soyeht.engine.plist` | LaunchDaemon (rejected: requires sudo to install, breaks SC-004) |
| macOS auto-update | Sparkle framework (1.x) bundled inside Soyeht.app | Custom updater (rejected: 6+ months engineering on a solved problem); App Store auto-update (rejected: sandbox limits engine port binding); `brew upgrade` (rejected per IV) |
| iOS distribution | App Store oficial (atualização da versão existente) | TestFlight permanent (rejected: 90-day expiry friction); Side-load via Developer Profile (rejected: 100 device cap, friction); Both parallel (rejected: doubled QA cost) |
| Linux engine residency | systemd user unit at `~/.config/systemd/user/soyeht-engine.service` (no sudo) | systemd system unit (rejected: sudo required, breaks SC-004); cron @reboot (rejected: no socket-activation, no graceful restart); foreground only (rejected: dies on terminal close) |
| Linux distribution | curl-pipe-sh from soyeht.com hosting tarball + script + sha256 | .deb/.rpm packages (rejected: distro-specific signing per distro, costlier QA matrix; deferred to v2); AppImage (rejected: no systemd user integration); Flatpak/Snap (rejected: sandbox conflicts with kernel keyring access) |
| Bonjour publisher | macOS: `bindgen` FFI to `dns_sd.h` (PR #42 base); Linux: existing `mdns-sd` crate | macOS Avahi-via-bonjour-bridge (rejected: extra dep, unstable); Linux dns_sd FFI (rejected: not idiomatic Linux, requires Avahi compat layer) |
| Bonjour service for setup | New `_soyeht-setup._tcp.` (separate from `_soyeht-household._tcp.`) | Reuse household service with state field (rejected: TXT bloat, semantic confusion: "máquina sem casa" vs "casa pronta") |
| Auto-pair credential transport | `GET /pair-machine/anchor-handoff` over Tailscale-ACL'd HTTPS | QR scan only (rejected: breaks SC-007 95% no-QR target); Bluetooth/AirDrop transport (rejected: no Tailscale-cross-LAN coverage) |
| Telemetry endpoint | Self-hosted Cloudflare Worker at `https://telemetry.soyeht.com` | Mixpanel/Segment (rejected: violates III local-first); No telemetry (rejected: blind to install failures) |
| `/bootstrap/teardown` auth | Owner cert signature (Phase 2 device cert) verified against `hh_pub`; iPhone biometric gate before signing | Tailnet ACL only (rejected per Q3 clarify); Mac/Linux local OS unlock (rejected: breaks zero-sudo) |
| Engine state directory | macOS: `~/Library/Application Support/Soyeht/`; Linux: `$XDG_DATA_HOME/Soyeht/` (defaulting to `~/.local/share/Soyeht/`) | Hidden dir `~/.theyos/` (rejected: legacy name; Constitution IV demands removal); `/usr/local/var/soyeht/` (rejected: requires sudo) |
| App-engine handshake | HTTP polling on `/bootstrap/status` until state changes | WebSocket push (rejected: complexity not justified for a state machine with ~5 transitions); D-Bus on Linux (rejected: macOS would need parallel impl) |

## Project Structure

### Documentation (this feature)

```text
specs/005-soyeht-onboarding/
├── spec.md                       # Feature specification (already written)
├── plan.md                       # This file (/speckit-plan command output)
├── research.md                   # Phase 0 output — technical decisions + rationale
├── data-model.md                 # Phase 1 — bootstrap state machine, entities, transitions
├── quickstart.md                 # Phase 1 — local dev/test walkthrough for engineers
├── contracts/                    # Phase 1 — wire-level CBOR/HTTP contracts
│   ├── bootstrap-status.md           # GET /bootstrap/status
│   ├── bootstrap-initialize.md       # POST /bootstrap/initialize
│   ├── bootstrap-teardown.md         # POST /bootstrap/teardown (owner cert auth)
│   ├── setup-invitation.md           # POST /bootstrap/claim-setup-invitation + _soyeht-setup._tcp.
│   ├── anchor-handoff.md             # GET /pair-machine/anchor-handoff (Tailnet capability)
│   └── bonjour-txt-enriched.md       # Updated _soyeht-household._tcp. TXT shape
└── tasks.md                      # Phase 2 output — created by /speckit-tasks
```

### Source Code (cross-repo)

```text
# theyos repo — Rust backend + install script + NixOS module
admin/rust/
├── server-rs/
│   └── src/
│       ├── handlers_bootstrap.rs           # NEW: /bootstrap/* endpoints + state machine
│       ├── handlers_pair_machine.rs        # MODIFIED: add /pair-machine/anchor-handoff
│       ├── bonjour_publisher.rs            # MODIFIED: enriched TXT + new _soyeht-setup service
│       ├── bonjour_browser.rs              # MODIFIED: browse _soyeht-setup for engine self-detect (rare)
│       ├── install_cli.rs                  # MODIFIED: refactored as internal callable, no longer user-facing CLI
│       ├── household_bootstrap.rs          # MODIFIED: state dir resolution (macOS Application Support, Linux XDG)
│       └── main.rs                         # MODIFIED: dispatch /bootstrap/* alongside existing routes
├── household-rs/
│   └── src/
│       ├── bootstrap_state.rs              # NEW: state machine enum + transitions + persistence
│       ├── setup_invitation.rs             # NEW: token mint/verify + TTL
│       └── owner_cert_auth.rs              # NEW: device cert signature verifier for teardown
├── core-rs/
│   └── src/
│       └── telemetry.rs                    # NEW: enum-closed event emitter, opt-in flag, PII strip
└── e2e-rs/
    └── tests/
        ├── caso_a_mac_founder.rs           # NEW: Mac founder + iPhone walkthrough
        ├── caso_b_iphone_first.rs          # NEW: iPhone-first → Mac install flow
        ├── linux_founder.rs                # NEW: Linux founder + iPhone walkthrough
        ├── linux_candidate_join.rs         # NEW: existing Mac casa + Linux entering as member
        └── bootstrap_state_machine.rs      # NEW: state transition tests

scripts/
├── install-linux.sh                        # NEW: curl-pipe-able install script (POSIX sh)
└── make.sh                                 # MODIFIED: package macOS engine into Soyeht.app/Contents/Helpers/

nix/
├── module.nix                              # MODIFIED: cfg.port in firewall.allowedTCPPorts; user-mode systemd unit option
└── flake.nix                               # MODIFIED: emit Soyeht-tagged outputs that NixOS module can consume

homebrew/
└── Formula/theyos.rb                       # MODIFIED → DELETED in same PR (Constitution IV); replaced by deprecation notice on soyeht.com

specs/005-soyeht-onboarding/
└── ... (above)
```

```text
# iSoyehtTerm repo — Swift apps (Mac + iOS)
TerminalApp/SoyehtMac/
├── Welcome/
│   ├── WelcomeRootView.swift               # MODIFIED: 3-second auto-discover → branch (founder/join/restore)
│   ├── TheyOSInstaller.swift               # MODIFIED → REPLACED: drop brew flow; new flow extracts engine from app bundle, drops LaunchAgent plist, launchctl bootstrap
│   ├── TheyOSAutoPairService.swift         # MODIFIED: integrate anchor-handoff endpoint
│   ├── TheyOSEnvironment.swift             # MODIFIED: Application Support state dir resolution
│   ├── TheyOSHealthProber.swift            # MODIFIED: poll /bootstrap/status (not just /health)
│   └── TheyOSUninstaller.swift             # MODIFIED → REPLACED: launchctl bootloader teardown + state dir cleanup; owner cert challenge
├── Onboarding/                             # NEW directory
│   ├── NameYourCasaView.swift              # NEW: "Como você quer chamar sua casa?"
│   ├── KeyBirthAnimationView.swift         # NEW: chave girando 3s with ✨
│   ├── CasaCardView.swift                  # NEW: cartão visual da casa
│   ├── RecoveryAssuranceView.swift         # NEW: "Sua casa é protegida pelas suas máquinas"
│   └── DiscoveredCasaPromptView.swift      # NEW: "Encontramos 'Sample Home' nesta rede" (User Story 5)
└── Bonjour/                                # MODIFIED
    └── SetupBeaconBrowser.swift            # NEW: browse _soyeht-setup._tcp. for Caso B reentry

TerminalApp/Soyeht/                         # iOS app
├── Welcome/                                # NEW directory
│   ├── CarouselView.swift                  # NEW: 5-card carrossel
│   ├── WhereToInstallView.swift            # NEW: "Tenho um Mac aqui" / "Tenho um Linux" / "Pegar o link depois"
│   ├── AirDropOrchestratorView.swift       # NEW: AirDrop progress + Bonjour beacon publish
│   ├── NameYourCasaIPhoneView.swift        # NEW: nome da casa digitado no iPhone (Caso B)
│   └── AddLinuxConfirmView.swift           # NEW: notificação rica "Adicionar Linux à Sample Home?"
├── Pairing/                                # MODIFIED
│   ├── AnchorHandoffClient.swift           # NEW: GET /pair-machine/anchor-handoff over Tailnet
│   ├── LocalAnchorPoster.swift             # NEW: POST /pair-machine/local/anchor (resolves Story 2 gap)
│   └── OwnerCertSigner.swift               # NEW: device cert signature for teardown requests
└── Bonjour/
    └── SetupBeaconPublisher.swift          # NEW: publish _soyeht-setup._tcp. with token (Caso B)

Packages/SoyehtCore/Sources/                # Shared between iOS + Mac
├── BootstrapStatus.swift                   # NEW: shared model for /bootstrap/status responses
├── SetupInvitationToken.swift              # NEW: token gen + serialization
└── EmojiSecurityCode.swift                 # NEW: BIP-39 wordlist → emoji deterministic mapping (FR-025)
```

**Structure Decision**: Cross-repo, mobile + API. The Rust engine stays in `theyos/admin/rust/`; the Swift apps stay in `iSoyehtTerm/TerminalApp/`. No new repository created. The shared protocol contracts live in `theyos/specs/005-soyeht-onboarding/contracts/` and are referenced by both sides via the cross-repo protocol contract pattern (`docs/household-protocol.md` already established).

## Phase 0 — Research outputs

The following items are resolved in the dedicated `research.md` (next step of /speckit-plan):

1. **LaunchAgent plist shape** — exact XML structure for the bundled engine, including `KeepAlive`, `RunAtLoad`, `WorkingDirectory`, `StandardErrorPath`, `StandardOutPath` paths, port environment.
2. **Programmatic AirDrop API** — confirm `UIActivityViewController` + `LSSupportsOpeningDocumentsInPlace` for sending the .dmg from iPhone Soyeht to Mac; alternative if blocked is `NSItemProvider` + custom share sheet.
3. **Sparkle integration** — Sparkle 2.x with EdDSA signing; appcast feed served from soyeht.com/appcast.xml; engine bundle re-extraction on app launch when Sparkle reports new install.
4. **Cross-compile Rust** — target triples for Linux x86_64-unknown-linux-gnu and aarch64-unknown-linux-gnu from macOS dev host (zig-cc or `cross`); CI matrix to produce both.
5. **Bonjour TXT enrichment** — backward-compat strategy with Phase 2/3 contracts already in field (additive keys only; downstream parsers ignore unknown keys per spec).
6. **Owner cert signing for teardown** — payload format (which fields signed: `{op:"teardown", hh_id, m_id, nonce, ts}` deterministic CBOR), signature format (raw 64-byte r||s P-256), iPhone Face ID gate flow.
7. **systemd user unit + linger** — when does engine survive logout? Default behavior + opt-in linger via `loginctl enable-linger` (single sudo call at install if user opts in; otherwise engine dies on logout).
8. **NixOS firewall fix** — `cfg.port` in `allowedTCPPorts` (resolves Story 2 walkthrough blocker — see FR-039).
9. **Engine binary size + bundle impact** — current `server` binary ~30MB; Soyeht.app bundle delta ~30-40MB; verify under App Store / Sparkle download size targets.
10. **iOS sandbox entitlements** — confirm Bonjour `_soyeht-setup._tcp.` browsing works with `NSLocalNetworkUsageDescription` + Bonjour services Info.plist entry; test against App Store sandbox before committing to AirDrop flow.

## Phase 1 — Design outputs (next /speckit-plan iteration)

After research.md is signed off:

- **`contracts/bootstrap-status.md`**: GET endpoint shape, JSON keys, state enum values, polling cadence guidance.
- **`contracts/bootstrap-initialize.md`**: POST CBOR body (`{name}` validation), response shape (`{hh_id, hh_pub, pair_qr_uri}`), state precondition (`uninitialized` or `ready_for_naming` only), error codes.
- **`contracts/bootstrap-teardown.md`**: POST CBOR body shape (signed envelope with owner cert), validation order, idempotency.
- **`contracts/setup-invitation.md`**: token mint shape (32 random bytes, TTL, hh_id_optional), POST `claim-setup-invitation` flow, Bonjour TXT `_soyeht-setup._tcp.` content.
- **`contracts/anchor-handoff.md`**: GET endpoint, Tailscale ACL gating (request originating IP must be in tailnet `100.64.0.0/10`), response (CBOR with `anchor_secret`).
- **`contracts/bonjour-txt-enriched.md`**: full TXT key list (existing + new), backward-compat rules, encoding.
- **`data-model.md`**: state machine diagram (Mermaid), entity ER (Casa, Máquina, Device pessoal, Convite de setup, Anchor secret), persistence layout under `household-state/`, transitions and side effects.
- **`quickstart.md`**: dev flow — clone repo, build engine locally, drop into Soyeht.app dev build, run iOS sim with the dev Mac, walk through Caso A end-to-end. Linux equivalent via NixOS dev VM.

## Re-evaluation post-Phase-1

After Phase 1 outputs land, re-check Constitution gates. Expected outcome: PASS on all 5 principles. Any new violation discovered during Phase 1 design must come back here as Complexity Tracking (below) before /speckit-tasks runs.

## Complexity Tracking

One justified Constitution-IV exception is recorded here. All other cross-cutting decisions in the matrix above stay within constitution principles without justification needed.

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| **Brew formula kept as deprecation stub instead of deleted** (Constitution IV "Adoption-First, No Legacy Compatibility" — same change set must remove old paths). The formula at `homebrew/Formula/theyos.rb` is updated to a stub that prints `Soyeht moved — visit https://soyeht.com/install` and exits non-zero, but the file is NOT deleted in this change set. | Existing brew tap users who run `brew upgrade theyos` after this lands need a graceful, discoverable redirect to the new flow. Hard-deleting the formula causes `brew` to throw `Error: No formulae or casks found` with no migration message — strictly worse user experience than the stub. | **Hard-delete the formula in the same PR**: rejected because it surfaces an opaque brew error to existing users with zero discovery path to the new flow. Graceful deprecation stub costs ~10 lines of Ruby and gives every brew user a single clear message; full removal will land in v0.3.0 once telemetry confirms zero brew installs (tracked as task on roadmap, NOT in this spec). The constitution's spirit (no parallel old/new code paths) is preserved because the stub is NOT a working old path — it's a redirect with no functional behavior. |

## Coordination notes

- This plan touches both `theyos` and `iSoyehtTerm` repos. PRs MUST be paired (theyos PR with new endpoints + iSoyehtTerm PR consuming them) and reference each other in description.
- Engine version and Soyeht.app version MUST stay locked-in-step; release pipeline already established for engine (PR #43 + PR #45 + PR #50). Extension: `make.sh` learns to package `Soyeht.app` with engine bundled.
- Cross-repo protocol contract `docs/household-protocol.md` to be updated alongside the contracts/ folder additions, as is custom for cross-repo schema changes (Constitution V).
- SoyehtCore `EmojiSecurityCode.swift` (FR-025 mapping) must agree byte-for-byte with the Rust-side BIP-39 wordlist mapping that produces the security code on the engine — define the lookup table in a shared spec asset (e.g., `specs/005-soyeht-onboarding/contracts/emoji-security-code-wordlist.csv`) consumed by both sides.

## Next step

Generate Phase 0 `research.md` resolving the 10 research items above. Then Phase 1 outputs. Then `/speckit-tasks` to decompose into actionable tasks.
