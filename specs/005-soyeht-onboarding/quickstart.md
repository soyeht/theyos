# Phase 1 — Quickstart: Soyeht Onboarding (dev walkthrough)

Branch: `005-soyeht-onboarding` | Spec: [spec.md](./spec.md) | Plan: [plan.md](./plan.md)

This document is the engineer-facing walkthrough for testing the new onboarding flow locally during development. It complements the user stories in `spec.md` by giving concrete commands and expected outputs.

## Prereqs (one-time setup)

### Mac dev box

```sh
# Rust toolchain (already required for theyos)
rustup target add aarch64-apple-darwin x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
cargo install cross --version "^0.2"

# Xcode + CLI tools (already required for SoyehtMac)
xcode-select --install

# Tailscale (recommended for testing auto-pair via Tailnet)
brew install --cask tailscale

# Sparkle dev tools (for testing auto-update)
brew install --cask sparkle
```

### Linux dev box (or NixOS VM)

```sh
# systemd user mode must be available (default on Ubuntu/Debian/Fedora/NixOS)
systemctl --user status

# Tailscale
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

## Caso A — Mac founder + iPhone (most common dev test)

### Build the Soyeht.app with bundled engine (dev variant)

```sh
cd ~/Documents/theyos
./scripts/make.sh package-soyeht-mac
# Produces: dist/macos-arm64/Soyeht.app (with Contents/Helpers/theyos-engine inside)
# Dev note: without THEYOS_CODESIGN_IDENTITY set, uses ad-hoc codesign (fine for local testing).
```

### Install on dev Mac

```sh
# Drag dist/macos-arm64/Soyeht.app to /Applications/
cp -R dist/macos-arm64/Soyeht.app /Applications/
# Or symlink for quick iteration:
ln -s "$(pwd)/dist/macos-arm64/Soyeht.app" /Applications/Soyeht.app
```

### Open Soyeht.app

Expected behavior:

1. Carousel of 5 cards plays.
2. After last card, "Vamos preparar seu Mac" screen. App copies engine from bundle to `~/Library/Application Support/Soyeht/engine/`. Drops LaunchAgent at `~/Library/LaunchAgents/com.soyeht.engine.plist`. Loads via `launchctl bootstrap`. Polls `GET http://127.0.0.1:8091/bootstrap/status` every 200 ms.
3. State `uninitialized` → `ready_for_naming` (engine startup checks complete, ~1-2 seconds).
4. UI shows "Como você quer chamar sua casa?" — type "Casa Dev". Enter.
5. App `POST /bootstrap/initialize {name: "Casa Dev"}`. Engine mints P-256 keypair (in software keystore for dev — `THEYOS_FORCE_SOFTWARE_KEYS=1` already in plist), persists. Returns `{hh_id, hh_pub, pair_qr_uri}`.
6. UI plays chave-girando animation 3s.
7. Cartão da casa renders with "Casa Dev" + Mac icon + ✨ "agora vamos adicionar seu iPhone".
8. Open Soyeht on iPhone (sim or hardware) on the same Tailnet. Notification rich appears: "Casa Dev te chamou. Entrar?" + Face ID.
9. Confirm. Both devices show "Pronto. Sua casa está pronta."

### Verify

```sh
# Engine running as LaunchAgent
launchctl print gui/$UID/com.soyeht.engine | head

# State persisted
ls -la ~/Library/Application\ Support/Soyeht/household-state/

# Bonjour publishing
dns-sd -B _soyeht-household._tcp. local
# Expect: "Casa Dev" SRV/TXT entries

# State machine
curl -s http://127.0.0.1:8091/bootstrap/status | jq
# Expect: {"state":"ready", "version":"...", "platform":"macos", ...}
```

### Tear down (reset)

```sh
# Triggers /bootstrap/teardown via SoyehtMac UI; requires Face ID on paired iPhone
# OR for raw dev:
curl -X POST http://127.0.0.1:8091/bootstrap/teardown \
  -H "Content-Type: application/cbor" \
  --data-binary @<signed-teardown-cbor>

# Cleanup LaunchAgent
launchctl unload ~/Library/LaunchAgents/com.soyeht.engine.plist
rm ~/Library/LaunchAgents/com.soyeht.engine.plist
rm -rf ~/Library/Application\ Support/Soyeht/
```

## Caso B — iPhone first, then Mac (AirDrop flow)

### Prerequisites

- Same Apple ID logged on both iPhone and Mac.
- AirDrop set to "Contacts Only" or "Everyone" temporarily.
- Mac has NO existing Soyeht install.

### Walkthrough

1. Open Soyeht on iPhone (no existing casa).
2. Carousel plays. After it, "Onde você quer instalar Soyeht?" screen.
3. Tap "Tenho um Mac aqui".
4. iPhone publishes `_soyeht-setup._tcp.` Bonjour beacon with token.
5. iPhone shows AirDrop sheet with nearby devices. User taps Mac entry.
6. Mac receives Soyeht.dmg via AirDrop. Opens automatically.
7. User drags Soyeht.app to /Applications. Opens it.
8. Soyeht.app on Mac, on first launch, scans `_soyeht-setup._tcp.` Bonjour. Finds the iPhone's beacon. POSTs `/bootstrap/claim-setup-invitation {token}` to its own engine (engine validates via callback to iPhone Bonjour endpoint).
9. App skips "Vamos preparar seu Mac" name screen — name appears on iPhone.
10. iPhone shows "Como você quer chamar sua casa?". User types. Enter.
11. iPhone POSTs `/bootstrap/initialize {name}` to Mac engine via Tailnet.
12. Mac mints keypair, returns hh_id. Both devices show "Pronto."

### Verify

```sh
# On Mac, engine state
curl -s http://127.0.0.1:8091/bootstrap/status | jq .state
# Expect: "ready"

# Bonjour beacons (Mac side, after pair complete)
dns-sd -B _soyeht-household._tcp. local
# Expect: Casa name visible

# iPhone Soyeht logs (Console.app filter "Soyeht")
# Expect: "Setup invitation claimed by Mac" → "Casa created" → "Owner-pairing complete"
```

## Linux founder (User Story 4)

### Build

```sh
cd ~/Documents/theyos
./scripts/make.sh package-engine-linux
# Produces both arches in one run:
#   dist/linux-x86_64/theyos-engine-<version>-linux-x86_64.tar.gz + .sha256
#   dist/linux-aarch64/theyos-engine-<version>-linux-aarch64.tar.gz + .sha256
```

### Install on Linux dev box

```sh
# As the user (NOT root)
curl -fsSL https://soyeht.com/install | sh
# Script: detects arch, downloads tarball, verifies sha256, extracts to ~/.local/share/Soyeht/,
# drops ~/.config/systemd/user/soyeht-engine.service, enables + starts.

# Verify
systemctl --user status soyeht-engine
curl -s http://127.0.0.1:8091/bootstrap/status | jq
# Expect: state=ready_for_naming
```

### Pair from iPhone

1. Open Soyeht on iPhone (no casa).
2. Bonjour discovers the Linux box advertising `_soyeht-setup._tcp.`. Notification rich: "Você quer começar uma casa neste Linux?".
3. Tap, name the casa, Face ID. Engine on Linux mints keypair (kernel keyring). Bonjour transitions to `_soyeht-household._tcp.`. iPhone first-paired.

### Verify

```sh
# Engine state
curl -s http://127.0.0.1:8091/bootstrap/status | jq
# Expect: state=ready

# Identity persisted
ls -la ~/.local/share/Soyeht/household-state/

# systemd unit alive
systemctl --user is-active soyeht-engine
# Expect: active

# Linger if opted in
loginctl show-user $USER | grep Linger
# Expect: Linger=yes (if opted in)
```

## Linux candidate (User Story 2 — adicionar Linux à casa existente)

### Setup

- Casa existente já em outro Mac/Linux na mesma Tailnet.
- iPhone do owner conectado.
- Linux box NEW, no Soyeht.

### Walkthrough

```sh
# On Linux box:
curl -fsSL https://soyeht.com/install | sh
# Engine sobe em estado uninitialized. Publisher Bonjour _soyeht-setup._tcp. up.
```

iPhone (já paireado à casa) detecta automaticamente via Bonjour. Notificação:
> *"Vimos um Linux novo na sua rede. Adicionar à Sample Home?"*
> *Código de segurança: ☕ café · 🪟 janela · 🌊 mar · 🌳 árvore · 🌙 lua · ⚡ raio*

Linux mostra os mesmos 6 emoji-palavras no terminal output do `soyeht-engine`. Owner bate de olho, confirma com Face ID. Linux entra como member.

### Verify

```sh
# On Linux:
curl -s http://127.0.0.1:8091/bootstrap/status | jq
# Expect: state=ready (joined as member, not founder)

# Identity loaded
ls ~/.local/share/Soyeht/household-state/household/
# Expect: household_record.cbor, self_m_id, machine_certs/<m_id>.cbor

# Bonjour
dns-sd -B _soyeht-household._tcp. local
# Expect: Sample Home visible from this Linux too (gossip happens after join)
```

## Troubleshooting

### "Engine doesn't start on Mac" (LaunchAgent failed)

```sh
launchctl print gui/$UID/com.soyeht.engine
# Look for "exit code"; common cause = port 8091 already bound by another process
lsof -i :8091
# Kill conflicting process or change THEYOS_HOUSEHOLD_PORT
```

### "Bonjour discovery doesn't find anything"

```sh
# Ensure Bonjour publisher is up
dns-sd -B _soyeht-setup._tcp. local
dns-sd -B _soyeht-household._tcp. local

# On Mac, verify publisher binding via dns_sd FFI (PR #42)
log stream --predicate 'subsystem == "com.soyeht.engine"' --info
# Look for "bonjour.publish.success" / "bonjour.candidate_published"

# On Linux, verify Avahi or mdns-sd publisher
journalctl --user -u soyeht-engine -f
# Filter for "bonjour"
```

### "iPhone doesn't see Mac's casa"

- Both devices on same Tailnet? `tailscale status` on Mac, `Settings → Tailscale` on iPhone.
- iOS Local Network permission granted to Soyeht? `Settings → Privacy → Local Network → Soyeht: ON`.
- Mac firewall allowing 8091/8892? `sudo pfctl -sr | grep 8091`.

### "Linux install script fails sha256 verify"

- Re-download: `curl -fsSL https://soyeht.com/install -o /tmp/install.sh && sha256sum /tmp/install.sh`.
- Compare against known-good hash on https://soyeht.com/install.sha256.

## Hardware walkthrough acceptance

The spec mandates hardware walkthroughs for all 4 scenarios (FR-041). For each:

1. Run the walkthrough on real hardware (Mac fresh, Linux fresh, iPhone fresh paired with the casa).
2. Time it from the trigger to "Sua casa está pronta" / "Linux entrou".
3. Record video (screen capture). Save to `specs/005-soyeht-onboarding/walkthroughs/<scenario>-<date>.mp4` (gitignored, reviewed in PR comments).
4. Verify SC-001..012 numbers measured.

The hardware walkthrough acts as the gate from /speckit-plan to /speckit-implement; if any walkthrough fails to meet success criteria, the spec/plan is amended before /speckit-tasks.
