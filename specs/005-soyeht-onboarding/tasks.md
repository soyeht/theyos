---
description: "Task list for 005-soyeht-onboarding implementation — agente-backend (theyos) scope only"
---

# Tasks: Soyeht Onboarding (Casa, primeiro Mac/Linux, paridade backend) — agente-backend tasks

**Input**: Design documents from `/specs/005-soyeht-onboarding/`
**Prerequisites**: plan.md (✓), spec.md (✓), research.md (✓), data-model.md (✓), contracts/ (✓), quickstart.md (✓)

**Scope**: This tasks.md contains ONLY tasks owned by **agente-backend** (theyos repo: Rust engine, install scripts, NixOS module, brew formula, contracts, CI/distribution). Tasks owned by **agente-front** (iSoyehtTerm repo: SoyehtMac + Soyeht iOS Swift code, Sparkle, App Store metadata, vocabulary CI lint) live in `iSoyehtTerm/specs/017-onboarding-canonical/tasks.md`. See "Cross-team boundary" section below for the moved tasks.

**Tests**: MANDATORY at protocol boundaries (per Constitution Engineering Standards: cert encode/decode/validate, signature verify, replication conflict resolution, Shamir round-trip).

**Out of scope for this spec (intentional, documented in spec.md FR-007 + plan.md):** Recovery flow UX (loss of iPhone → restoration via Shamir reconstruction from another casa machine). The bootstrap state machine reserves the `recovering` state and the persistence layout supports Shamir shards across members, but no user-facing recovery UI is implemented here. Recovery flow has its own future spec — provisional ID `007-recovery-flow` — which depends on this spec landing first.

**Hardware walkthrough iteration policy:** if a Success Criterion (SC-001..012) is missed by ≤20% on hardware walkthrough, file a follow-up optimization task and proceed; if missed by >20%, return to plan amendment phase before continuing implementation.

## Format: `[ID] [P?] [Story] Description`

- **[P]** = can run in parallel (different files, no shared dependencies)
- **[Story]** = US1..US5 / Foundation / Polish
- All paths under `theyos/` repo unless noted

## Path Conventions

- **theyos repo** (this scope): `admin/rust/<crate>/src/...`, `nix/`, `scripts/`, `homebrew/Formula/`, `docs/`, `specs/005-soyeht-onboarding/`, `tests/fixtures/`
- Cross-cutting joint artifacts (`specs/005-soyeht-onboarding/contracts/*.md`, `specs/005-soyeht-onboarding/contracts/*.csv`) are SHARED — both repos consume from theyos source-of-truth.

---

## Cross-team boundary — agente-front domain (NOT in this tasks.md)

The following implementation tasks live in `iSoyehtTerm/specs/017-onboarding-canonical/tasks.md` (agente-front's authoritative scope):

- **All Swift code** in `Packages/SoyehtCore/Sources/`, `TerminalApp/SoyehtMac/`, `TerminalApp/Soyeht/` (iOS app).
- **iSoyehtTerm directory structures** (Welcome/, Onboarding/, Pairing/, Bonjour/SetupBeacon/...).
- **SoyehtCore shared models**: `BootstrapStatus.swift`, `EmojiSecurityCode.swift`, `OwnerCertSigner.swift`, `SetupInvitationToken.swift`.
- **SoyehtMac Welcome flow refactor**: `TheyOSInstaller.swift`, `WelcomeRootView.swift`, `TheyOSHealthProber.swift`, `TheyOSAutoPairService.swift`, `TheyOSUninstaller.swift`.
- **5 SwiftUI Onboarding views** + **`RequiresLoginItemsApprovalView`** (SMAppService approval UX), **`ContinuityCameraView`**, **`KeyHandoffMetaphorView`** — all under iSoyehtTerm Onboarding/.
- **Soyeht iOS Welcome flow**: `CarouselView.swift` (5 cards), `WhereToInstallView.swift`, `AirDropOrchestratorView.swift`, `NameYourCasaIPhoneView.swift`, `AddLinuxConfirmView.swift`, `DiscoveredCasaPromptView.swift`.
- **Bonjour clients (Swift)**: `SetupBeaconBrowser.swift` (Mac), `SetupBeaconPublisher.swift` (iPhone), `HouseholdBonjourBrowser` updates, **Tailnet trust filter Swift-side** (mirrors my engine-side T015a; default Tailnet, opt-in LAN bruta with security notice).
- **Pairing clients (Swift)**: `AnchorHandoffClient.swift`, `LocalAnchorPoster.swift` (resolves Story 2 Phase 3 gap), `PairingPresenceServer.swift` updates.
- **Sparkle 2.x integration** in SoyehtMac, including engine-version sentinel verification on app launch (FR-030 enforcement Swift-side), hardened-runtime entitlements (`com.apple.security.cs.disable-library-validation`).
- **Sparkle appcast.xml** generation via iSoyehtTerm release CI (per cross-team decision — appcast hosted at soyeht.com, maintained by frontend release pipeline).
- **APNs registration (iOS-side)**: `UNUserNotificationCenter.requestAuthorization`, `registerForRemoteNotifications`, token forwarding to backend `POST /push/register-device-token`, notification handling.
- **Soyeht.dmg bundling** in iOS app bundle for AirDrop.
- **Settings UI** for telemetry opt-in toggle, "Reapresentar tour" deliberate revival of carousel.
- **Vocabulary CI lint** (greps Swift LocalizedStringResource + xliff for banned words) + string sweep PT-BR/EN/15-language localization.
- **App Store metadata** (screenshots, feature blurb, Privacy Manifest compliance).
- **All XCTest + XCUITest** for the above.
- **Hardware walkthrough user-facing measurement** (Caso A/B/Story 4/Story 5) — engine-side measurement is mine; user-side experience and timing is his.

Cross-cutting joint ownership (BOTH repos consume from a single source of truth):
- `specs/005-soyeht-onboarding/contracts/*.md` — endpoint shapes, Bonjour TXT keys, fixture file paths. Source of truth in **theyos**; iSoyehtTerm references via mirror header.
- `specs/005-soyeht-onboarding/contracts/emoji-security-code-fixtures.csv` — generated by my T017a, consumed by both Rust + Swift implementations. Byte-equal verification in CI.
- `specs/005-soyeht-onboarding/contracts/avatar-derivation-fixtures.csv` — generated by my T017b, same pattern.
- `tests/fixtures/owner_cert_auth.cbor` — generated by my T080a, consumed by Swift OwnerCertSigner tests via build phase.
- `docs/household-protocol.md` §16a (threat model) — maintained in theyos, referenced from iSoyehtTerm contracts.

Cross-repo CI gate: **T040d** (this repo) verifies contract markdown drift between repos via the `<!-- mirror of theyos:005/contracts/... as of <hash> -->` header pattern.

---

## Phase 1: Setup (shared infrastructure)

**Purpose**: Project initialization, toolchains, CI matrix updates.

- [X] **T001** [theyos] Verify worktree `~/Documents/theyos-worktrees/005-soyeht-onboarding` on branch `005-soyeht-onboarding` is the source of truth for this feature. (Already established during /speckit-specify run.)
- [X] **T002** [theyos] Add Linux cross-compile targets to `admin/rust/Cargo.toml` workspace metadata: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`. Install `cross` (https://github.com/cross-rs/cross) in dev environment.
- [X] **T003** [theyos] [P] Update `.github/workflows/release-macos.yml` (or new `release.yml`) to add Linux build matrix with **TWO explicit jobs** — `build-linux-x86_64` and `build-linux-aarch64`. Each job uses `cross` with the corresponding target triple, produces `dist/linux-<arch>/soyeht-engine-<version>.tar.gz` plus `<file>.sha256` sidecar, and uploads to the GitHub Release. Matrix cache key per-arch to avoid cache contention. Smoke-test the binary boots in a minimal container (alpine + glibc shim per T016) before declaring the job green.
- [X] **T004** [theyos] [P] Add `scripts/install-linux.sh` skeleton (POSIX sh, idempotent, downloads from soyeht.com, verifies sha256, installs to `~/.local/share/Soyeht/`). Stub only at this phase; filled in Phase 4.
- [X] **T006** [theyos] [P] Create `specs/005-soyeht-onboarding/contracts/emoji-security-code-wordlist.csv` with the deterministic mapping `BIP-39 EN word index → emoji + Unicode codepoint`. Source of truth for both Rust (T017) and Swift (in agente-front scope) implementations of FR-025. BIP-39 wordlist in **English** as input invariant; UI display labels are localized separately.

**Checkpoint**: Foundation tooling ready. CI builds engine for both Mac and Linux. Worktree wiring confirmed.

---

## Phase 2: Foundational (blocking prerequisites for ALL user stories)

**Purpose**: State machine, endpoints scaffolding, Bonjour service infrastructure.

**⚠️ CRITICAL**: No user story phase can begin until this phase completes.

### Engine state machine + endpoints

- [X] **T007** [theyos] [Foundation] Create `admin/rust/household-rs/src/bootstrap_state.rs` defining `enum BootstrapState { Uninitialized, ReadyForNaming, NamedAwaitingPair, Ready, Recovering }`. Add `transition()` method enforcing valid transitions per `data-model.md`. Add `persist()` / `load()` for `identity.bootstrap_state` on disk. Tests for every transition (valid + invalid → typed error).
- [X] **T008** [theyos] [Foundation] Create `admin/rust/server-rs/src/handlers_bootstrap.rs` with module skeleton; export router `pub fn bootstrap_router(state: BootstrapStateArc) -> Router`. No handler bodies yet — this PR just wires routing.
- [X] **T009** [theyos] [Foundation] Implement `GET /bootstrap/status` per `contracts/bootstrap-status.md`. Returns 200 JSON with state machine state + version + platform + host_label + uptime + hh_id (nullable) + device_count. Polling cadence verified <200 ms response. Contract test covering response shape and field types.
- [X] **T010** [theyos] [Foundation] Implement `GET /health` (or confirm existing matches expected shape: 200 OK if engine alive, no body required). Contract test.
- [X] **T011** [theyos] [Foundation] Update `admin/rust/server-rs/src/main.rs` so engine boots in `uninitialized` (skip household_bootstrap auto-init when state dir is empty). Listeners for `/bootstrap/*` and `/health` always up; `/api/v1/*` returns 503 with `{state: "uninitialized"}` body when not in `ready`.
- [X] **T012** [theyos] [Foundation] Update `admin/rust/server-rs/src/household_bootstrap.rs::resolve_household_state_dir` to default to `~/Library/Application Support/Soyeht/` on macOS, `$XDG_DATA_HOME/Soyeht/` (with `~/.local/share/Soyeht/` fallback) on Linux. Keep `THEYOS_DIR` env override for dev/test. Tests for both platforms.

### Bonjour TXT + new setup service

- [X] **T013** [theyos] [Foundation] Implement `admin/rust/server-rs/src/bonjour_publisher.rs` enrichment per `contracts/bonjour-txt-enriched.md`. Add `hh_name`, `owner_display_name`, `device_count`, `platform`, `bootstrap_state`, `host_label` keys to existing `_soyeht-household._tcp.` TXT. Backward-compat verified by running test against Phase 2/3 parser fixtures.
- [X] **T014** [theyos] [Foundation] Implement new Bonjour service `_soyeht-setup._tcp.` per `contracts/setup-invitation.md`. Publishes when engine in `uninitialized` / `ready_for_naming`. Disambiguation TXT key `setup_role` ∈ `{founder_candidate, member_candidate}` (set after 5s discovery if engine sees existing `_soyeht-household._tcp.` in tailnet). Withdraws when state advances. Tests covering publish/withdraw lifecycle + role determination.
- [X] **T015** [theyos] [Foundation] Update `admin/rust/server-rs/src/bonjour_browser.rs` to add `_soyeht-setup._tcp.` browser. Engine's own browser logs detected setup invitations to facilitate audit/debug. Tests.
- [X] **T015a** [theyos] [P] [Foundation] Implement **Tailnet trust filter** in the Bonjour browser layer (per FR-015). Create `admin/rust/server-rs/src/bonjour_trust.rs` exposing `enum DiscoverySource { Tailnet, LocalNetwork }` and a filter that classifies each discovered service by source IP at resolution time. By default browser only emits `Tailnet` results to consumers. Add explicit opt-in `BrowserConfig { include_local_network: bool }` for fallback flows. Tests cover: Tailnet IP → emitted, LAN IP → suppressed, IPv6 Tailnet → emitted, IPv6 LAN → suppressed.
- [X] **T016** [theyos] [Foundation] Engine binary standalone audit: ensure `server-rs` binary has no runtime dependency on `brew` env, `systemd` env, or `nix` env beyond what `THEYOS_DIR` declares. Add CI integration test that runs the binary in a minimal Docker container (alpine:3.19 + glibc shim) to detect missing deps.
- [X] **T016a** [theyos] [P] [Foundation] Add Linux multi-interface Bonjour regression test `admin/rust/server-rs/tests/bonjour_linux_smoke.rs` mirroring the existing `bonjour_macos_smoke.rs` (PR #42 base). Boots a test engine on a multi-interface Linux container, publishes both `_soyeht-household._tcp.` and `_soyeht-setup._tcp.`, asserts TXT records visible from a peer browser on each interface.
- [X] **T016b** [theyos] [P] [Foundation] Extend existing `bonjour_macos_smoke.rs` to assert ALL new TXT keys present on the publisher: `hh_name`, `owner_display_name`, `device_count`, `platform`, `bootstrap_state`, `host_label`.

### Cross-language fixture generation (joint artifacts produced here)

- [X] **T017** [theyos] [P] [Foundation] Implement Rust side of FR-025 emoji security code in `admin/rust/household-rs/src/emoji_code.rs`. Loads `emoji-security-code-wordlist.csv` at compile time (via `include_str!`); function `derive_emoji_code(m_pub: &P256Public, nonce: &[u8; 32], hostname: &str) -> [String; 6]` returns 6 emoji-words. Tests for determinism + cross-language byte equality.
- [X] **T017a** [theyos] [P] [Foundation] Generate cross-language fixture file `specs/005-soyeht-onboarding/contracts/emoji-security-code-fixtures.csv` with 50 deterministic test triples — `(m_pub_hex, nonce_hex, hostname) → expected_word_1..6`. Use a seedable CSPRNG (ChaCha20 with seed `b"soyeht-onboarding-fixture-2026"`). Cross-repo CI fails on any byte divergence between Rust (T017) and Swift (agente-front scope) implementations.
- [X] **T017b** [theyos] [P] [Foundation] Generate cross-language avatar derivation fixture `specs/005-soyeht-onboarding/contracts/avatar-derivation-fixtures.csv` with 1000 deterministic entries — `(hh_pub_hex → expected_emoji_unicode, h, s, l)`. Algorithm per iSoyehtTerm spec FR-046 + research.md R4 (curated 512-emoji catalog + SHA-256 derivation): `hash = SHA-256(hh_pub); emoji_idx = u32_be(hash[0..4]) % 512; color_h = u16_be(hash[4..6]) % 360; color_s = 60 + (hash[6] % 26); color_l = 50 + (hash[7] % 21)`. Seed: `b"soyeht-onboarding-avatar-fixture-2026"`.

**Checkpoint**: Foundation ready. State machine functional. Endpoints scaffolded. Bonjour publishes correctly. Cross-language fixtures generated. User story phases can now begin.

---

## Phase 3: User Story 1 — Mac founder + iPhone (Priority: P1) 🎯 MVP

### Tests

- [X] **T021** [theyos] [P] [US1] Contract test for `POST /bootstrap/initialize` per `contracts/bootstrap-initialize.md`. CBOR shape, name validation edge cases, state precondition checks.
- [X] **T022** [theyos] [P] [US1] Integration test `admin/rust/e2e-rs/tests/caso_a_mac_founder.rs`: simulates SoyehtMac flow against a local engine in test mode. Asserts state transitions `uninitialized → ready_for_naming → named_awaiting_pair → ready` happen in expected sequence. Uses fake Phase 2 owner-pairing client.

### Implementation

- [X] **T025** [theyos] [US1] Implement `POST /bootstrap/initialize` in `handlers_bootstrap.rs` per contract. Uses Phase 2 keypair gen (existing `household_rs::generate_household_keypair`). Atomic persist via existing helpers. Returns `InitializeResponse` with `pair_qr_uri` from existing Phase 2 `PairDeviceWindow::with_persistence`. Logs `tracing::info!(stage = "bootstrap.initialized", hh_id = ...)`.
- [X] **T026** [theyos] [US1] Update Phase 2 owner-pairing finalize handler to drive the `named_awaiting_pair → ready` transition (write `identity.bootstrap_state = "ready"`, update Bonjour TXT `device_count`).
- [X] **T034** [theyos] [P] [US1] Engine-side hardware walkthrough Caso A: instrument `/bootstrap/status` polling latency, `/bootstrap/initialize` execution time, Bonjour publish latency. Coordinate with agente-front user-side walkthrough (paired). Engine measurements feed SC-001 (<60s end-to-end).

**Checkpoint**: User Story 1 engine-side functional + tested. Cross-team handoff: agente-front delivers UX side; my engine responds correctly.

---

## Phase 4: User Story 2 — Linux candidate joining existing casa (Priority: P1)

### Tests

- [X] **T035** [theyos] [P] [US2] Contract test for `GET /pair-machine/anchor-handoff` per `contracts/anchor-handoff.md`. Tailnet ACL gating (mock IPv4 `100.64.0.0/10`), 403 for non-tailnet IPs, response shape.
- [X] **T036** [theyos] [P] [US2] Integration test `admin/rust/e2e-rs/tests/linux_candidate_join.rs`: simulates a Linux machine joining an existing casa via the auto-pair Tailnet path. Verifies `_soyeht-setup._tcp.` Bonjour beacon on Linux + iPhone discovery + anchor-handoff + Phase 3 finalize end-to-end. Asserts no QR generated/displayed.

### Linux install script

- [X] **T039** [theyos] [US2] Fill in `scripts/install-linux.sh` (started in T004): detects arch (`uname -m`), downloads `dist/linux-<arch>/soyeht-engine-<version>.tar.gz` from soyeht.com, verifies sha256, extracts to `~/.local/share/Soyeht/engine/`, generates `~/.config/systemd/user/soyeht-engine.service` per `research.md` R7, runs `systemctl --user daemon-reload && enable --now soyeht-engine`. Asks "Manter Soyeht ativo mesmo deslogado?" — if yes, runs `sudo loginctl enable-linger $USER` (the only sudo prompt). Idempotent. **Firewall detection (FR-038):** runs `command -v ufw && sudo ufw status` and `systemctl is-active firewalld` checks. If active, outputs message: *"Firewall detectado. Soyeht escuta em portas 8091 e 8892. Como sua casa é descoberta via Tailscale (`tailscale0` interface), você não precisa abrir as portas para a internet pública. Mas se quiser permitir descoberta também na sua rede local (não recomendado para servidor exposto), rode: `sudo ufw allow 8091/tcp && sudo ufw allow 8892/tcp` (UFW) ou equivalente."* Never auto-modifies firewall rules.
- [ ] **T040** [theyos] [US2] Test `install-linux.sh` against Ubuntu 22.04, Debian 12, Fedora 38, NixOS 24.05. Assert engine starts in `uninitialized` state, publishes `_soyeht-setup._tcp.` Bonjour, no errors in journalctl.

### Engine

- [X] **T041** [theyos] [US2] Implement `GET /pair-machine/anchor-handoff` per `contracts/anchor-handoff.md` in `handlers_pair_machine.rs`. Source IP check (Tailnet CGNAT + IPv6 ULA), pair_machine_window load, fingerprint via emoji code, response. Tests cover 403/404/410 + 200 success.
- [X] **T042** [theyos] [US2] Update `_soyeht-setup._tcp.` Bonjour publisher (T014) `setup_role` field to disambiguate "machine without casa" (founder candidate, Story 4) vs "machine awaiting candidate-join" (member candidate, Story 2).
- [X] **T043** [theyos] [US2] Wire owner approval flow (existing Phase 3 `JoinRequestStagingClient.approve`) to trigger anchor-handoff initiated from iPhone, then standard Phase 3 finalize. Verify state transitions logged in `tracing` and replicated to other casa machines.
- [X] **T048** [theyos] [P] [US2] Engine-side hardware walkthrough Story 2: instrument anchor-handoff response time, `local/anchor` POST latency, finalize completion time. Coordinate with agente-front user-side walkthrough. SC-003 < 30s.

**Checkpoint**: User Story 2 engine-side functional. Linux machines join existing casa via iPhone Face ID without QR scan.

---

## Phase 5: User Story 3 — iPhone primeiro, depois Mac (Caso B AirDrop) (Priority: P2)

### Tests

- [X] **T049** [theyos] [P] [US3] Contract test `POST /bootstrap/claim-setup-invitation` per `contracts/setup-invitation.md`. Token validation, callback verify, IP source check on subsequent `/bootstrap/initialize`.
- [X] **T050** [theyos] [P] [US3] Integration test `admin/rust/e2e-rs/tests/caso_b_iphone_first.rs`: simulates iPhone → Mac AirDrop flow with mocked Bonjour beacon publisher + verification callback. Asserts `/bootstrap/initialize` only succeeds when source IP matches iPhone's tailnet IP.

### Engine

- [X] **T053** [theyos] [US3] Implement `POST /bootstrap/claim-setup-invitation` per contract. State gate (uninitialized only), token shape check, Bonjour cache lookup, TTL check, callback verify against iPhone endpoint, persist `household-state-pending/setup-invitation.cbor` (in-memory + disk for crash recovery). **Includes new optional field `iphone_apns_token`** (32 bytes APNs device token); when present, persisted alongside setup invitation for `casa_nasceu` push delivery later (T088b). When absent, Caso B falls back to Bonjour-only flow.
- [X] **T054** [theyos] [US3] Add Tailnet IP-source guard to `POST /bootstrap/initialize`: when a setup invitation is pending, require source IP matches iPhone's resolved Bonjour endpoint AND falls within Tailnet ranges. Tests cover hijack attempt → 403; LAN bruta initialize attempt → 403 with `{v:1, error:"tailnet_required"}`.

**Checkpoint**: User Story 3 engine-side functional. Mac engine cooperates with iPhone-first onboarding via Bonjour beacon handshake.

---

## Phase 6: User Story 4 — Linux founder + iPhone (Priority: P2)

### Tests

- [ ] **T064** [theyos] [P] [US4] Integration test `admin/rust/e2e-rs/tests/linux_founder.rs`: simulates Linux fresh + iPhone fresh + Tailnet. Asserts iPhone discovers `_soyeht-setup._tcp.` with `setup_role=founder_candidate`, POSTs `/bootstrap/initialize` to Linux, owner-pair finalizes.

### Engine

- [X] **T066** [theyos] [US4] Tag Bonjour `_soyeht-setup._tcp.` advertisements with `setup_role=founder_candidate` when engine is in `uninitialized` AND no casa exists in the Tailnet (i.e., Linux is the first machine). Detection: at boot, engine browses `_soyeht-household._tcp.` for 5s; if zero results, sets role accordingly.

**Checkpoint**: User Story 4 engine-side functional. Linux can be founder, fully iPhone-driven.

---

## Phase 7: User Story 5 — Adicionar segundo Mac à casa existente (Priority: P3)

### Tests

- [ ] **T069** [theyos] [P] [US5] Integration test `admin/rust/e2e-rs/tests/second_mac_join.rs`: existing casa + fresh second Mac + Tailnet. Asserts auto-discovery shows existing casa, anchor-handoff via Tailnet succeeds, second Mac member-joined.

**Checkpoint**: User Story 5 engine-side validated.

---

## Phase 8: Cross-cutting — Teardown flow

### Tests

- [X] **T074** [theyos] [P] Contract test `POST /bootstrap/teardown` per contract: 6-step validation order, replay protection (nonce), clock skew, owner cert chain.
- [X] **T075** [theyos] [P] Integration test `admin/rust/e2e-rs/tests/teardown_flow.rs`: full teardown round-trip + state machine reset.

### Engine

- [X] **T077** [theyos] Implement `POST /bootstrap/teardown` in `handlers_bootstrap.rs` per `contracts/bootstrap-teardown.md`. Six-step validation, atomic state-dir teardown, listener unbinds, Bonjour reverts. Tracing logs every step.
- [X] **T078** [theyos] Add nonce replay cache: `recent-nonces/<hex>` directory with 24h TTL eviction. Bounded to 100k entries (oldest evicted).
- [X] **T079** [theyos] Create `admin/rust/household-rs/src/owner_cert_auth.rs`: verifier for owner cert chain (D_pub → P_priv → hh_priv → hh_pub) tied to existing Phase 2 cert chain code.
- [X] **T080a** [theyos] [P] Generate owner cert fixture binary `tests/fixtures/owner_cert_auth.cbor` containing 5 variants: (a) valid TeardownRequest with valid signature; (b) signature mismatch; (c) `ts` skew >300s; (d) replayed nonce; (e) `signed_by` not in household device set. Document generator in `tests/fixtures/owner_cert_auth/README.md` with seed for reproducibility. Cross-language: agente-front imports via build phase script in iSoyehtTerm SoyehtCore tests.

**Checkpoint**: Teardown flow secure + tested engine-side.

---

## Phase 9: Cross-cutting — Distribution + auto-update (engine-side)

- [X] **T082** [theyos] Update `scripts/make.sh` to add `package-soyeht-mac` target: builds Rust engine for macOS arm64, signs with Developer ID (existing PR #43 pipeline), wraps into Soyeht.app/Contents/Helpers/. Re-uses existing notarization step.
- [X] **T083** [theyos] [P] Update `scripts/make.sh` to add `package-engine-linux` target: cross-compiles Rust engine for Linux x86_64 + ARM64, packages each into tar.gz with sha256 sidecar, places in `dist/linux-<arch>/`.
- [X] **T086** [theyos] [P] Update `.github/workflows/release.yml`: build matrix produces both Mac DMG (with engine bundled) and Linux tarballs (x86_64 + ARM64). Notarize Mac. Upload all to GitHub Release. **Engine version sentinel (FR-030):** during `package-soyeht-mac` step, write `Soyeht.app/Contents/Helpers/engine-version.txt` containing the **exact** CFBundleVersion of the .app being built (single source of truth = `git describe --tags`). The engine binary itself reads this file on startup and reports the value through `GET /bootstrap/status.version`. CI gate: if engine binary's compile-time version differs from the version sentinel, fail the package step. (Sparkle appcast.xml generation owned by agente-front; my pipeline only produces the .dmg + sentinel.)
- [ ] **T087** [Out-of-repo] Set up `https://soyeht.com/install` endpoint that serves the install-linux.sh script + sha256, plus a static download page for Soyeht.dmg. Cloudflare Pages or similar (out of scope for this repo, but tracked here for completion).
- [X] **T040d** [theyos] [P] Create cross-repo contracts diff verifier workflow `.github/workflows/contracts-cross-repo-sync.yml`. Triggers on PR push to `005-soyeht-onboarding` branch. Action: clones iSoyehtTerm repo at the commit-hash referenced in each mirror header (`<!-- mirror of theyos:005/contracts/<file>.md as of <hash> -->`), diffs each contract markdown file against its theyos source-of-truth, fails the workflow if any drift detected. agente-front adds the equivalent task in iSoyehtTerm pointing back to this workflow. Constitution V structural enforcement: cross-repo contracts cannot drift silently.

**Checkpoint**: Distribution pipeline functional from theyos side. Mac DMG + Linux tarballs publishable; appcast feed maintained by agente-front.

---

## Phase 10: Cross-cutting — Telemetry (engine-side)

- [ ] **T088** [theyos] [P] **DEFERRED — Constitution Principle III violation (R7-A).** Cloud telemetry endpoint learns source IP → per-installation fingerprint even with PII strip; engine startup/transitions are control-plane events. Requires constitution amendment + plan.md Complexity Tracking entry before re-implementation. Original scope: enum-closed event emitter posting to `https://telemetry.soyeht.com/event`.
- [X] **T088b** [theyos] Implement `admin/rust/core-rs/src/apns_push.rs` — APNs gateway client per `contracts/push-events.md` and `research.md` R11. Loads `.p8` provider key from `Soyeht.app/Contents/Resources/apns.p8` (or `THEYOS_APNS_P8_PATH` env override for Linux/dev), generates JWT auth, HTTP/2 POST to `api.push.apple.com`. Wire `casa_nasceu` event emission into `handlers_bootstrap.rs::initialize_handler` per the v1 contract trigger conditions: emit iff state transition `ready_for_naming → named_awaiting_pair` succeeded AND pending setup invitation has non-empty `iphone_apns_token`. Retries on 5xx with exponential backoff (1s/2s/4s/8s/16s/30s cap); aborts on 4xx with `tracing::warn!` + Bonjour-only fallback. Tests: payload shape conformance, retry/abort semantics, Caso A path (no push emitted), Caso B path with token (push emitted), Caso B path no token (no push, graceful).
- [X] **T088c** [theyos] [P] Generate cross-language fixture `tests/fixtures/casa_nasceu_push.json` containing 5 deterministic test entries (using a seedable CSPRNG with seed `b"soyeht-onboarding-casa-nasceu-fixture-2026"`) — each entry is a `(input_state_tuple, expected_aps+soyeht_payload_json)` pair. Inputs: `(hh_id, hh_name, machine_id, machine_label, pair_qr_uri, ts)`. Expected output: full APNs JSON envelope per `contracts/push-events.md`. Document the generator in `tests/fixtures/casa_nasceu_push/README.md`. Cross-language: agente-front T067b imports this fixture into Swift `CasaNasceuPushPayloadTests.swift` via build phase, validates byte-equal payload generation/parsing across Rust+Swift impls. CI fails on any divergence.
- [ ] **T090** [Out-of-repo] [P] Set up Cloudflare Worker at `telemetry.soyeht.com` accepting JSON event POSTs. Forwards to internal log. Tracked here for completion; not blocking spec land.

**Checkpoint**: Telemetry engine-side functional + privacy-respecting.

---

## Phase 12: Cross-cutting — NixOS module fix

- [X] **T093** [theyos] Update `nix/module.nix` `networking.firewall.allowedTCPPorts` to include `cfg.port` (admin panel, default 8892) and new `cfg.householdPort` option (default 8091, exposed in module options block). Smoke test on a clean NixOS install. Resolves Story 2 walkthrough firewall blocker (FR-039).
- [X] **T094** [theyos] [P] Document NixOS install path alongside curl path in README. Both equally first-class.

**Checkpoint**: NixOS firewall no longer blocks LAN candidate-join.

---

## Phase 13: Cross-cutting — Brew formula deprecation (Constitution IV)

- [X] **T095** [theyos] Update `homebrew/Formula/theyos.rb` to a deprecation stub: a no-op formula whose `install` block runs `odie "Soyeht moved — visit https://soyeht.com/install for the new flow"` (so `brew install` exits non-zero with that exact line as the user's only output). Removes ALL functional behavior — no parallel old/new paths execute. **Constitution-IV justification documented in plan.md "Complexity Tracking"**: stub kept (not deleted) so `brew upgrade theyos` shows the redirect message instead of an opaque "formula not found" error to existing users; full file deletion scheduled for v0.3.0 once telemetry confirms zero brew install attempts.
- [ ] **T096** [Out-of-repo] [P] Update soyeht.com landing page to feature direct Soyeht.dmg download as primary CTA; brew tap secondary with deprecation notice.

**Checkpoint**: Migration path clear. Old users gracefully redirected.

---

## Phase 14: Polish + cross-cutting

- [X] **T097** [theyos] [P] Update `docs/household-protocol.md` cross-references to spec 005 endpoints + Bonjour service. Already partially done (§16a threat model). Final audit + sync with iSoyehtTerm contract mirrors.
- [X] **T100** [theyos] [P] Run `quickstart.md` validation: an engineer follows quickstart.md end-to-end on a new dev environment and confirms each step works as documented. File any gaps as bugs.
- [ ] **T101** [theyos+iSoyehtTerm] Final hardware walkthrough series (FR-041): all 5 user stories validated on real hardware, video recorded. SC-001..012 measured. JOINT — agente-front does user-side measurement, I do engine-side instrumentation.
- [ ] **T102** [theyos+iSoyehtTerm] PR pair (theyos + iSoyehtTerm) opened, cross-referenced, code review by team, merge via admin (PRs are large — paired review).
- [ ] **T103** [theyos] Tag `v0.2.0` (next major engine release reflecting onboarding rewrite). Update CHANGELOG.

**Checkpoint**: Spec 005-soyeht-onboarding fully delivered.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: No deps. Start immediately.
- **Phase 2 (Foundational)**: Depends on Phase 1. **BLOCKS all user stories.**
- **Phase 3 (US1)**: Depends on Phase 2.
- **Phase 4 (US2)**: Depends on Phase 2 + Phase 3 (need a casa to join).
- **Phase 5 (US3)**: Depends on Phase 2 + Phase 3 (Mac flow as base).
- **Phase 6 (US4)**: Depends on Phase 2 + Phase 4 (Linux install script).
- **Phase 7 (US5)**: Depends on Phase 2 + Phase 4 (anchor-handoff endpoint).
- **Phase 8 (Teardown)**: Depends on Phase 3 (need casa to teardown).
- **Phase 9 (Distribution)**: Depends on Phase 3 + Phase 4 ship-ready code.
- **Phase 10 (Telemetry)**: Independent of Phase 3-7; can start after Phase 2.
- **Phase 12 (NixOS fix)**: Independent; can start anytime.
- **Phase 13 (Brew deprecation)**: Depends on Phase 9 (new flow must work before deprecating old).
- **Phase 14 (Polish)**: Depends on Phases 3-13 substantially complete.

### Cross-team coordination dependencies

- agente-front Phase 3 (Welcome flow + onboarding views) depends on T009 (`/bootstrap/status` endpoint live), T013 (Bonjour TXT enriched), T015a (Tailnet trust filter contract).
- agente-front Phase 4 (AnchorHandoffClient + LocalAnchorPoster) depends on T041 (`anchor-handoff` endpoint live), `anchor-handoff.md` contract finalized.
- agente-front Phase 5 (AirDrop + Caso B) depends on T053/T054 (`claim-setup-invitation` + IP guard live), T080a (owner cert fixture available).
- My Phase 9 (engine-version sentinel in T086) depends on agente-front having Sparkle integration ready to read it.

### MVP Strategy

- **MVP = Phase 1 + Phase 2 + Phase 3 (US1)**. Delivers core Mac founder + iPhone pair flow. Can ship as v0.2.0-alpha.
- **Beta = MVP + Phase 4 (US2)**. Adds Linux candidate-join. Self-host story complete.
- **GA = all phases**. Includes iPhone-first AirDrop, Linux founder, second-Mac, teardown, distribution polish.

## Parallel Execution Examples

- T002, T003, T004, T006 (Setup) can run in parallel.
- T013, T014, T015 (Bonjour work) sequential (same file `bonjour_publisher.rs`).
- T021, T022 (tests for US1) parallel.
- T035, T036 (tests for US2) parallel.
- T041, T042, T043 (US2 engine) sequential (T041 binds endpoint; T042 enriches publisher; T043 wires existing flow).

## Validation

- [ ] All FRs that fall in agente-backend scope have implementation tasks here.
- [ ] All endpoints in `contracts/` have test + implementation tasks engine-side.
- [ ] All entities in `data-model.md` have implementation tasks engine-side.
- [ ] Cross-team boundary section above lists everything moved to agente-front.
- [ ] Cross-cutting joint artifacts (contracts, fixtures, threat model) clearly identified as shared.
- [ ] Hardware walkthroughs T034/T048 + T101 paired with agente-front user-side walkthroughs.
- [ ] All success criteria SC-001..012 measured + documented at the joint walkthrough phase.
