# macOS Setup Guide

Run theyOS on macOS using Apple Virtualization Framework instead of Firecracker.

## Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Mac hardware | Apple Silicon (M1/M2/M3/M4) | Intel x86_64 not supported |
| macOS version | 14 (Sonoma) | 15+ recommended; guest macOS version must be <= host version |
| Disk space | 100 GB free | Base image ~64 GB + IPSW ~18 GB + snapshots |
| RAM | 16 GB | 8 GB allocated per VM, host needs headroom |
| Rust toolchain | 1.92+ | Pinned in `admin/rust/rust-toolchain.toml` |
| Node.js | 22+ | For frontend build |
| Xcode CLT | Latest | `xcode-select --install` |
| Passwordless sudo | Required | For APFS mount + SSH host key generation during init |

## How it works

On Linux, theyOS runs claw instances inside **Firecracker microVMs** (KVM). On macOS, it uses **Apple Virtualization Framework (VZ)** which provides similar isolation with native performance on Apple Silicon.

```
Linux path:  server-rs → executor-rs → vmrunner-rs     → Firecracker (KVM)
macOS path:  server-rs → executor-rs → vmrunner-macos-rs → VZ Framework
```

Platform selection is compile-time (`#[cfg(target_os = "macos")]`), not runtime.

### Key differences from Linux

| | Linux (Firecracker) | macOS (VZ) |
|--|---------------------|------------|
| Hypervisor | KVM | Virtualization.framework |
| Guest OS | Linux (NixOS) | macOS |
| Boot time (cold) | ~15-20s | ~30-60s |
| Boot time (warm pool) | <1s | <2s |
| Disk cloning | cp --reflink | APFS CoW (`cp -c`) |
| Max concurrent VMs | Unlimited | 2 (Apple license) |
| Networking | Firecracker netns | VZ NAT (192.168.64.x) |
| SSH transport | fc-ssh | theyos-ssh |

## Initial setup

### 1. Configure passwordless sudo

Required for the init process (APFS mount, SSH host key generation, file ownership).

```bash
sudo visudo
```

Add at the bottom:

```
<your-username> ALL=(ALL) NOPASSWD: ALL
```

### 2. Build the project

```bash
cd admin/rust
cargo build --release
```

### 3. Codesign the VM runner binary

Apple Virtualization Framework requires the `com.apple.security.virtualization` entitlement:

```bash
codesign --force \
  --entitlements scripts/entitlements/vmrunner-macos.entitlements \
  -s - admin/rust/target/release/vmrunner_macos_ipc
```

> **Important:** You must re-sign after every rebuild of `vmrunner_macos_ipc`.

### 4. Initialize the macOS base image

This downloads a macOS IPSW (~18 GB), installs macOS in a VM, provisions it with SSH + Homebrew + developer tools, and creates a snapshot for instant cloning.

```bash
THEYOS_VMRUNNER_MACOS_RS_BIN=admin/rust/target/release/vmrunner_macos_ipc \
  admin/rust/target/release/init_macos_guest --cpus 4 --memory-mb 8192
```

**First run takes ~25-30 minutes.** The process is resumable — if interrupted, re-run the same command.

What gets installed in the base image:
- macOS (matching host version)
- Homebrew
- tmux, Python 3, Node.js
- Claude Code, OpenCode
- SSH server (com.theyos.sshd LaunchDaemon)

### 5. Start the admin backend

```bash
# Set environment
export THEYOS_VMRUNNER_MACOS_RS_BIN=$(pwd)/admin/rust/target/release/vmrunner_macos_ipc
export THEYOS_SSH_CTL=$(pwd)/admin/rust/target/release/theyos-ssh

# Start
soyeht admin-host-start
```

### 6. Verify

```bash
curl http://localhost:8892/healthz
```

Then open `http://localhost:8892` in your browser.

## Creating instances

Once the base image is ready, create claw instances via the admin panel or API:

```bash
curl -X POST http://localhost:8892/api/v1/instances/create \
  -H "Content-Type: application/json" \
  -d '{"type": "picoclaw", "customer": "test-1"}'
```

The first instance takes ~30-60s (cold boot). Subsequent instances use the warm pool (<2s).

## Rebuilding the base image

After updating claw binaries or tools:

```bash
THEYOS_VMRUNNER_MACOS_RS_BIN=admin/rust/target/release/vmrunner_macos_ipc \
  admin/rust/target/release/init_macos_guest --force-provision
```

This re-injects binaries and rebuilds the snapshot (~5 min) without reinstalling macOS.

## Troubleshooting

### "Unable to connect to installation service"

The `vmrunner_macos_ipc` binary is missing the VZ entitlement. Re-sign it:

```bash
codesign --force \
  --entitlements scripts/entitlements/vmrunner-macos.entitlements \
  -s - admin/rust/target/release/vmrunner_macos_ipc
```

### "A software update is required to complete the installation"

theyOS first tries to find a restore image that matches this Mac automatically.
If this error still appears, a compatible signed restore image was not found. Update macOS:

```bash
softwareupdate --list
sudo softwareupdate --install "macOS Tahoe <version>" --restart
```

Or re-run with a matching restore image explicitly:

```bash
theyos init-macos-guest --ipsw ~/Downloads/UniversalMac_<version>_<build>_Restore.ipsw
```

If automatic lookup still fails, the CLI prints a ready-to-paste block and a direct issue link:

```text
https://github.com/soyeht/theyos/issues/new?template=macos-restore-image.yml
```

### "Rust cannot catch foreign exceptions, aborting"

Files in the base image directory are owned by root (usually from running `init_macos_guest` with `sudo`). Fix:

```bash
sudo chown -R $(whoami):staff ~/Library/Application\ Support/theyos/vms/macos-base/
```

### SSH timeout during init

sshd is not starting inside the VM. Common causes:

1. **Missing SSH host keys** — Re-run init; the code now generates them automatically
2. **File ownership wrong** — The APFS mount needs `-o owners` to persist UID/GID
3. **Stale DHCP lease** — The MAC address fix ensures consistent IP across reboots

### VM not reachable after creation

Check that the VM got a DHCP lease:

```bash
cat /var/db/dhcpd_leases | grep -A 3 "ip_address"
```

Check the VM IP file:

```bash
cat ~/Library/Application\ Support/theyos/vms/<container>/vm_ip
```

### Port 22 "Connection refused"

sshd didn't start. Check if host keys exist:

```bash
# Attach and mount the VM disk, then:
ls /private/etc/ssh/ssh_host_*
```

If missing, the `fix_sshd_after_first_boot` function should generate them. Re-run `--force-provision`.

## Clean reinstall via Homebrew

Use this when `brew uninstall theyos` is not enough and you want a truly clean reinstall.

### 1. Capture a baseline

```bash
df -h ~
brew services info theyos || true
launchctl list | grep theyos || true
ps -axo pid=,command= | grep -E 'theyos|soyeht|vmrunner' | grep -v grep || true
```

### 2. Stop Homebrew helpers and purge user data

```bash
soyeht cleanup-homebrew --purge-data
```

This stops the admin backend, stops `brew services`, kills leftover `libexec` helpers, removes the `LaunchAgent`, deletes logs/caches/temp DBs, and purges `~/.theyos` plus the VM data under `~/Library/Application Support/theyos`.

If purge fails with `EACCES`, check `macos-base` ownership before retrying:

```bash
ls -la ~/Library/Application\ Support/theyos/vms/macos-base/
sudo chown -R $(whoami):staff ~/Library/Application\ Support/theyos/vms/macos-base/
soyeht cleanup-homebrew --purge-data
```

### 3. Uninstall the formula

```bash
brew uninstall theyos
```

### 4. Verify the machine is clean

```bash
launchctl list | grep theyos || true
ps -axo pid=,command= | grep -E 'theyos|soyeht|vmrunner' | grep -v grep || true
find ~/Library/Application\ Support/theyos -user root 2>/dev/null || true
df -h ~
```

### 5. Reinstall and validate

```bash
brew install theyos
theyos --help
soyeht start
grep SOYEHT_ADMIN_PASSWORD ~/.theyos/.env
curl -sf http://localhost:8892/healthz
init_macos_guest status
```

`/healthz` only proves the admin backend is up. `init_macos_guest status` confirms whether the macOS base image has actually finished downloading/installing/provisioning.

## File locations

| Type | Path |
|------|------|
| Base image | `~/Library/Application Support/theyos/vms/macos-base/` |
| Instance disks | `~/Library/Application Support/theyos/vms/<container>/` |
| Snapshots | `~/Library/Application Support/theyos/snapshots/` |
| SSH keys | `~/.theyos/keys/id_ed25519` |
| Init state | `~/Library/Application Support/theyos/vms/macos-base/init-state.json` |
| Logs | `~/Library/Logs/theyos/` |
| Config | `~/.theyos/config.yaml` |

## Limitations

1. **Apple Silicon only** — VZ Framework requires arm64
2. **Max 2 macOS VMs** — Apple license limits simultaneous macOS guests per host
3. **Guest <= host version** — Cannot install macOS newer than the host
4. **Snapshots not portable** — VZ snapshots only work on the machine that created them
5. **No Firecracker on macOS** — KVM is Linux-only; macOS uses VZ exclusively
6. **Codesigning after rebuild** — Must re-sign `vmrunner_macos_ipc` after every `cargo build`
