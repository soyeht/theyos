# theyOS

An operating system for AI agents. Each agent ("claw") gets its own isolated virtual machine with full computer access — terminal, filesystem, networking, dev tools. You manage everything from a single admin panel or the iOS app.

## Why

AI coding agents need a real computer to operate, not just an API. theyOS gives each agent its own VM with:

- A full OS (macOS or Linux) with terminal, package managers, and dev tools pre-installed
- Isolation between agents — one agent can't see or break another's environment
- Instant provisioning — create a new agent environment in under 2 seconds
- Central management — admin panel + iOS app to monitor and control all agents

## Linux vs macOS

theyOS runs on both platforms with different strengths:

| | Linux (Firecracker) | macOS (Virtualization Framework) |
|---|---|---|
| **VM technology** | Firecracker microVMs (same tech as AWS Lambda) | Apple Virtualization Framework |
| **Boot time** | ~150ms cold boot | ~15s cold boot |
| **Density** | Hundreds of VMs per host | 2 macOS VMs per host (Apple license) |
| **Warm pool** | Pre-booted VMs, <1s create | Pre-booted VMs, <2s create |
| **Best for** | Multi-tenant production, high density | Personal use, macOS-native dev environments |
| **Networking** | Unprivileged (slirp4netns) | NAT (VZ managed DHCP) |
| **OS** | NixOS host, Ubuntu guests | macOS host, macOS guests |

## Install

### macOS

Download **Soyeht.app** from [soyeht.com/install](https://soyeht.com/install), open it, and follow the on-screen setup. The app guides you through naming your casa and pairing your iPhone as the owner key.

**Requirements:** Apple Silicon (M1/M2/M3/M4), macOS 14+, 100 GB free disk space.

### Linux — release installer

```bash
curl -fsSL https://soyeht.com/install | sh
```

The script installs the engine under `~/.local/share/Soyeht`, creates the
user-level `soyeht-engine.service`, and starts the service.

**Requirements:** Linux with systemd user services, x86_64 or aarch64, and KVM
support.

### Linux — NixOS flake module

Add theyOS as a flake input and enable the module — the same method the curl installer uses under the hood:

```nix
# flake.nix
{
  inputs.theyos.url = "github:soyeht/theyos";

  outputs = { self, nixpkgs, theyos, ... }: {
    nixosConfigurations.myserver = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        theyos.nixosModules.theyos
        {
          services.theyos = {
            enable        = true;
            adminPort     = 8892;   # default — admin panel
            householdPort = 8091;   # default — household identity listener
          };
        }
      ];
    };
  };
}
```

Then rebuild: `sudo nixos-rebuild switch --flake .#myserver`

**Requirements:** NixOS 24.05+, x86_64 with KVM support, flakes enabled.

### Update

```bash
# macOS — Soyeht.app updates itself; check for updates in the app menu.

# Linux
sudo soyeht update
```

### Uninstall

```bash
# macOS
# Use Soyeht > Uninstall Soyeht... in the app, or Uninstall Soyeht.app
# from the DMG if the main app was already deleted.

# Linux
soyeht uninstall
```

If the `soyeht` binary is missing or damaged, use the recovery endpoint:

```bash
curl -fsSL https://soyeht.com/uninstall | sh
```

See [docs/uninstall.md](docs/uninstall.md) for details.

## Accessing the Admin Panel

| Mode | URL | Notes |
|------|-----|-------|
| **Local** | `http://localhost:8892` | Works immediately |
| **Tailscale** | `http://<machine>:8892` | Access from any device on your tailnet |
| **Tailscale + Caddy** | `https://<machine>.<tailnet>.ts.net` | Auto HTTPS (Linux with Caddy) |
| **Public domain** | `https://your-domain.com` | Cloudflare Tunnel |

Your admin password is generated on first run:

```bash
grep SOYEHT_ADMIN_PASSWORD ~/.theyos/.env
```

## iOS App

The iOS app (iSoyehtTerm) connects to your theyOS server via QR code. From your phone you can:

- View and manage all agent instances
- Open terminal sessions to any agent's VM
- Create and delete instances
- Monitor resource usage

Pair your phone: open the admin panel, go to an instance, and scan the QR code.

## Supported Claws

Claws are installed from the **Claw Store** in the admin panel. Each claw gets its own VM:

| Claw | Language | Description |
|------|----------|-------------|
| PicoClaw | Go | Lightweight AI assistant |
| ZeroClaw | Rust | Advanced features, high performance |
| Nanobot | Python | Data-driven AI agent |
| OpenClaw | Node.js | Full-stack AI environment |
| NullClaw | Zig | Identity/passthrough (testing) |
| IronClaw | Rust | Full-featured, complex setup |

Fresh installs start with zero claws. Install what you need from the Claw Store.

## Management

```bash
soyeht start              # Start all services
soyeht stop               # Stop all services
soyeht status             # Show status
soyeht health             # Run health checks
soyeht logs               # Follow logs
```

## Architecture

```
                    ┌──────────────┐
                    │   iOS App    │
                    └──────┬───────┘
                           │
  localhost ───┐           │
  Tailscale ───┼──► Admin Backend (Rust, :8892)
  Cloudflare ──┘           │
                    ┌──────┴───────┐
                    │  IPC layer   │
                    ├──────────────┤
             ┌──────┤  VM Runner   ├──────┐
             │      └──────────────┘      │
     ┌───────▼────────┐          ┌────────▼───────┐
     │  Firecracker   │    or    │  Apple VZ      │
     │  microVMs      │          │  macOS VMs     │
     │  (Linux)       │          │  (macOS)       │
     └────────────────┘          └────────────────┘
        picoclaw                    picoclaw
        zeroclaw                    zeroclaw
        nanobot                     nanobot
        openclaw                    openclaw
        ...                         ...
```

The admin backend is a Rust workspace with 18 crates. Each concern (store, executor, terminal, VM runner) runs as an IPC subprocess. The VM runner is selected at compile time: `vmrunner-rs` (Firecracker) on Linux, `vmrunner-macos-rs` (VZ) on macOS.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Rust 1.92, axum 0.8, tokio, rusqlite |
| Frontend | React 19, TypeScript, Vite 7 |
| Database | SQLite |
| Linux VMs | Firecracker microVMs |
| macOS VMs | Apple Virtualization Framework |
| iOS | SwiftUI + WebSocket terminals |
| Proxy | Caddy (optional, for HTTPS) |
| Host OS | NixOS (Linux) or macOS 14+ (Mac) |

## License

MIT
