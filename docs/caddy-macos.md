# Caddy on macOS

theyOS needs a Caddy reverse proxy for two features: public claw sites
(`livre.org`, `personasgpt.ai`, etc.) and local HTTPS (`https://admin.localhost`).
On NixOS, Caddy is installed and supervised declaratively via `services.caddy`.
On macOS, soyeht owns the Caddy lifecycle through a per-user LaunchAgent and a
local CA in the System keychain.

This doc explains exactly what theyOS does to your Mac, how to inspect it, and
how to remove it cleanly.

## What gets installed

1. **The Caddy binary** — only if you consent. The `./install` script detects
   an existing `caddy` (PATH, `brew --prefix caddy`, `/opt/homebrew/bin/caddy`,
   `/usr/local/bin/caddy`, `/opt/local/bin/caddy`). If none is found and
   Homebrew is installed, it offers `brew install caddy`. Default is **no**.
   Pass `--with-caddy` for unattended installs, or `--no-caddy` to skip
   entirely.

2. **Caddy's local CA in the System keychain** — installed by `caddy trust`
   during `soyeht setup`. macOS shows a GUI password dialog. This enables
   real HTTPS for `https://admin.localhost` and `https://*.localhost` without
   browser warnings. Skipped if you decline the prompt.

3. **A LaunchAgent**: `~/Library/LaunchAgents/com.soyeht.caddy.plist`. Boots
   Caddy at user login, restarts on crash, logs to
   `~/Library/Logs/theyos/caddy.{out,err}.log`. Skipped if you decline the
   prompt.

That's it. theyOS **never** touches `/opt/homebrew/etc/Caddyfile`, `brew
services`, or any LaunchAgent it didn't create.

## What does NOT get installed

- No system-level LaunchDaemon (we use a per-user LaunchAgent).
- No `brew services start caddy` (that points to the brew-managed Caddyfile,
  which would conflict with theyOS's).
- No edits to `/etc/hosts` (the `*.localhost` wildcard works via mDNS).
- No firewall changes.

## How it runs

The LaunchAgent invokes:

```
caddy run --config <repo>/distro/caddy/Caddyfile --adapter caddyfile
```

Caddy listens on:

- `:8080` — HTTP, used by Cloudflare Tunnel for public claw sites and by the
  legacy admin proxy paths.
- `:443` — HTTPS, used by `admin.localhost` and `*.localhost` (Caddy internal
  CA).
- `:2019` — admin API on `localhost`, used by `soyeht caddy reload` for
  zero-downtime config swaps.

The Caddyfile is the same one used in production NixOS. macOS-specific blocks
are gated by hostname (`admin.localhost`, `*.localhost`) and dormant in
production.

## Common operations

```sh
soyeht caddy install     # detect + write plist + bootstrap
soyeht caddy status      # binary, plist, agent, admin API health
soyeht caddy start       # auto-detects path drift, regenerates plist if needed
soyeht caddy stop        # bootout the agent
soyeht caddy restart     # launchctl kickstart -k
soyeht caddy reload      # zero-downtime config reload via admin API
soyeht caddy logs        # tail caddy.out.log
soyeht caddy logs --err  # tail caddy.err.log
soyeht caddy trust       # install local CA (re-prompts password)
soyeht caddy untrust     # remove local CA from System keychain
soyeht caddy uninstall   # bootout + remove plist (does NOT untrust)
```

## Inspecting the install

```sh
# LaunchAgent plist (XML, human-readable)
cat ~/Library/LaunchAgents/com.soyeht.caddy.plist

# launchctl view
launchctl print "gui/$(id -u)/com.soyeht.caddy"

# Trusted Caddy CA in the System keychain
security find-certificate -c "Caddy Local Authority" /Library/Keychains/System.keychain

# Caddy admin API
curl -s http://localhost:2019/config/ | head
```

## Path drift

If you move the repo (e.g. `~/theyos` → `~/Documents/theyos`), the plist
points at the old path. The next `soyeht caddy start` detects the mismatch,
regenerates the plist, boots out the stale agent, and bootstraps the new one.
You don't need to run `soyeht caddy uninstall` first.

If something goes wrong (permissions, plist corruption, etc.), force a clean
reinstall:

```sh
soyeht caddy uninstall
soyeht caddy install
```

## Removing theyOS's Caddy from your Mac

To leave Caddy itself but remove theyOS's involvement:

```sh
soyeht caddy uninstall   # removes LaunchAgent + plist
soyeht caddy untrust     # removes the local CA from the System keychain
```

To remove Caddy entirely (only if theyOS was the reason you installed it):

```sh
brew uninstall caddy     # if installed via brew
```

Logs persist at `~/Library/Logs/theyos/caddy.{out,err}.log` until you delete
them manually.

## Coexistence with another Caddy install

If you already run Caddy for another project, theyOS's Caddy will conflict on
ports 8080, 443, or 2019. `soyeht caddy install` and `soyeht caddy start`
detect the conflict via `lsof`, print the offending PID and command, and
abort. They never kill foreign processes. You have two options:

- Stop your other Caddy before starting theyOS's.
- Edit `distro/caddy/Caddyfile` to use different ports (and update the rest
  of the stack to match — `8080` and `2019` are referenced from
  `admin/rust/server-rs/src/public_sites.rs` and the NixOS module).

## Why `caddy trust`

Browsers reject self-signed certs with hard warnings. `caddy trust` installs
the Caddy local CA into the System keychain so browsers see HTTPS sites
served by Caddy as fully trusted on your Mac.

The CA is **local-only** — it cannot sign certificates for any host other
than ones you serve through this Caddy instance. Other people's machines do
not trust it. Removing it (`soyeht caddy untrust`) does not affect any other
HTTPS site you visit.

## Why a LaunchAgent and not a subprocess of soyeht

The LaunchAgent gives you:

- Automatic start at user login.
- Restart on crash (`KeepAlive=true`).
- Survives `soyeht stop`, `soyeht restart`, and shell logouts.
- Integration with `launchctl` for status, logs, and kickstart.

A child process of `soyeht` would die when soyeht dies, requiring you to keep
a terminal open. For a service that should be available whenever you're
logged in, the LaunchAgent is the right tool — exactly the same pattern brew
uses for `brew services`, but pointed at theyOS's Caddyfile instead of brew's.
