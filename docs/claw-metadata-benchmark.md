# Claw Metadata Benchmark Report

**Date**: 2026-04-07
**Host**: <prod-host> — 56 cores, 80 GB RAM, Firecracker VMs
**Operator**: Claude Code (automated via SSH from Mac)

## Purpose

Collect real values for four metadata fields planned for the Claw Store:

- `version` — semver of the installed build
- `binary_size_mb` — disk footprint in MB
- `min_ram_mb` — minimum RAM for the VM to run the claw
- `license` — SPDX license identifier

These values replace the mock placeholders in the catalog.

## Methodology

### version

Ran `<claw> --version` inside a live Firecracker VM for each claw type.
For noclaw (a bundle of three CLI tools), collected each tool's version separately.

**Command pattern:**
```
fc-ssh exec <container> "<claw> --version 2>&1 | head -5"
```

### binary_size_mb

Two categories of claws require different measurement approaches:

**Compiled binaries** (nullclaw, picoclaw, zeroclaw, ironclaw):
Measured the actual binary file on disk inside the VM.

```
fc-ssh exec <container> "stat -c%s /usr/local/bin/<claw>"
```

Report: file size in bytes, converted to MB (÷ 1,048,576).

**Interpreted runtimes** (nanobot, openclaw, hermes-agent, noclaw):
These have no meaningful single binary — the entry point is a tiny wrapper script
(117–217 bytes). The useful metric is **total install footprint**: the runtime,
source code, and all dependencies on disk.

```
# Python claws (nanobot, hermes-agent):
fc-ssh exec <container> "du -sm /usr/local/lib/python*/dist-packages/"
fc-ssh exec <container> "du -sm /opt/claws/<claw>/"

# Node.js claws (openclaw):
fc-ssh exec <container> "du -sm /opt/claws/<claw>/"

# noclaw (global npm packages):
fc-ssh exec <container> "du -sm /usr/lib/node_modules/"
```

Report: total directory size in MB from `du -sm`.

**Important**: when comparing binary_size_mb across claws, note that compiled
binaries (nullclaw=3 MB, picoclaw=30 MB) are self-contained executables, while
interpreted claws (openclaw=2360 MB) include the full dependency tree. These
numbers are not directly comparable — they answer different questions:
- Compiled: "how big is the binary I ship?"
- Interpreted: "how much disk does the full install consume?"

### license

Queried the GitHub API for each upstream repository's SPDX license identifier.
This is the license detected by GitHub from the repo's LICENSE file.

```
gh api repos/<owner>/<repo> --jq '.license.spdx_id'
```

Cross-referenced against the manifest.yml source URLs.

### min_ram_mb

This is the most complex metric. The approach:

1. **Measure RSS (Resident Set Size)** of the claw gateway process running idle
   inside a VM with 2048 MB RAM (the system default).

   ```
   fc-ssh exec <container> "<claw> gateway -E &>/tmp/log & sleep 5; \
     for p in $(pgrep -f <claw>); do grep VmRSS /proc/$p/status; done"
   ```

2. **Add VM OS overhead** (~100 MB for Ubuntu 24.04 minimal in Firecracker).

3. **Apply safety margin** (round up to next power-of-two-friendly value).

   ```
   min_ram_mb = next_bucket(RSS + 100 MB OS)
   buckets: 128, 256, 512, 1024, 2048
   ```

**Limitation**: Several claws (nullclaw, nanobot, hermes-agent, ironclaw) require
API keys or database config to start their gateway. For these, the gateway process
exited immediately, so RSS was estimated from:
- The runtime's typical baseline (Go ~20 MB, Rust ~15 MB, Python ~50 MB)
- The binary size loaded into memory
- Comparison with similar claws where RSS was measured

**Caveat**: RSS at idle is the floor, not the ceiling. Under load (active AI
conversations, tool execution), memory usage can be 2–10x higher. The min_ram_mb
is "minimum to boot and idle", not "minimum to serve production traffic".

**System constraint**: The theyOS API enforces a floor of 512 MB for `ram_mb`.
Values below 512 in the manifest are informational — they tell users "this claw
is lightweight" even though the VM will always get at least 512 MB.

## Results

### Raw measurements

| Claw | version | binary (bytes) | install_size_mb | RSS gateway (kB) | RSS method |
|------|---------|---------------|-----------------|-------------------|------------|
| nullclaw | 2026.3.1 | 3,157,464 | 3 | N/A (needs config) | estimated |
| picoclaw | 0.2.5 | 30,757,048 | 30 | 23,584 | measured |
| zeroclaw | 0.1.9 | 25,476,488 | 25 | 16,948 | measured |
| nanobot | 0.1.5 | 217 (wrapper) | 270 | N/A (needs API key) | estimated |
| openclaw | 2026.4.6 | 117 (wrapper) | 2,360 | 299,592 | measured |
| noclaw | (bundle) | N/A | 866 | N/A (CLI, no daemon) | estimated |
| hermes-agent | 0.7.0 | N/A (wrapper) | 263 | N/A (needs API key) | estimated |
| ironclaw | 0.12.0 | 76,346,448 | 73 | N/A (needs DB) | estimated |

Noclaw tool versions: Claude Code 2.1.92, OpenCode 1.3.17, Codex 0.118.0.

### Derived values for the Claw Store

| Claw | version | binary_size_mb | min_ram_mb | license |
|------|---------|---------------|------------|---------|
| nullclaw | 2026.3.1 | 3 | 128 | MIT |
| picoclaw | 0.2.5 | 30 | 256 | MIT |
| zeroclaw | 0.1.9 | 25 | 256 | Apache-2.0 |
| nanobot | 0.1.5 | 270 | 512 | MIT |
| openclaw | 2026.4.6 | 2360 | 512 | MIT |
| noclaw | (bundle) | 866 | 2048 | proprietary |
| hermes-agent | 0.7.0 | 263 | 1024 | MIT |
| ironclaw | 0.12.0 | 73 | 512 | Apache-2.0 |

### Latest versions available (GitHub/PyPI, not necessarily installed)

| Claw | Installed | Latest | Source |
|------|-----------|--------|--------|
| nullclaw | 2026.3.1 | 2026.4.4 | GitHub releases |
| picoclaw | 0.2.5 | 0.2.5 | GitHub releases |
| zeroclaw | 0.1.9 | 0.1.7-beta.1 (tag) | GitHub tags (no releases) |
| nanobot | 0.1.5 | 0.1.5 | PyPI |
| openclaw | 2026.4.6 | 2026.4.5 | GitHub releases |
| noclaw | N/A | N/A | npm (3 packages) |
| hermes-agent | 0.7.0 | 2026.4.3 | GitHub releases |
| ironclaw | 0.12.0 | 0.24.0 | GitHub releases |

Note: zeroclaw installed version (0.1.9) is newer than the latest GitHub tag
(0.1.7-beta.1) because it was built from the `main` branch HEAD.

## How to re-run this benchmark

### Prerequisites

- SSH access to your prod host (configured via `~/.ssh/config`): `ssh <prod-host>`
- All 8 claws installed in the claw store (status "ready")
- At least one running instance per claw type

### Steps

1. **Authenticate with the admin API:**
   ```bash
   PASS=$(grep SOYEHT_ADMIN_PASSWORD "$THEYOS_HOME/theyos/.env" | cut -d= -f2-)
   echo -n "{\"username\":\"admin\",\"password\":\"$PASS\"}" > /tmp/login.json
   TOKEN=$(curl -s -D - http://localhost:8892/api/v1/auth/login \
     -H "Content-Type: application/json" -d @/tmp/login.json \
     | grep -oE 'soyeht_session=[^;]+' | head -1 | cut -d= -f2)
   S="soyeht_session=$TOKEN"
   ```

2. **Ensure all claws are installed:**
   ```bash
   curl -s -b "$S" http://localhost:8892/api/v1/claws
   # If any show "not_installed", install via:
   curl -s -b "$S" -X POST http://localhost:8892/api/v1/claws/<name>/install
   ```

3. **Create one instance per claw** (if none exist):
   ```bash
   for CLAW in nullclaw picoclaw zeroclaw nanobot openclaw noclaw hermes-agent ironclaw; do
     curl -s -b "$S" -X POST http://localhost:8892/api/v1/instances \
       -H "Content-Type: application/json" \
       -d "{\"name\":\"bench-$CLAW\",\"claw_type\":\"$CLAW\"}"
     # Fix empty subdomain bug (if still present):
     sqlite3 "$THEYOS_HOME/theyos/.run/theyos.db" \
       "UPDATE instances SET subdomain = 'bench-$CLAW' WHERE name = 'bench-$CLAW'"
   done
   ```

4. **Collect version + binary size:**
   ```bash
   FC="$THEYOS_HOME/theyos/admin/rust/target/release/fc-ssh"
   for CLAW in nullclaw picoclaw zeroclaw ironclaw; do
     echo "=== $CLAW ==="
     $FC exec ${CLAW}-bench-${CLAW} "$CLAW --version 2>&1 | tail -3"
     $FC exec ${CLAW}-bench-${CLAW} "stat -c%s /usr/local/bin/$CLAW"
   done
   # For interpreted claws, use du -sm on the install directory instead.
   ```

5. **Collect RSS (start gateway, wait, measure):**
   ```bash
   # Example for picoclaw:
   $FC exec picoclaw-bench-picoclaw \
     "picoclaw gateway -E &>/tmp/gw.log & sleep 5; \
      for p in \$(pgrep -f picoclaw); do \
        grep VmRSS /proc/\$p/status; \
      done"
   ```
   Gateway startup flags vary per claw:
   - picoclaw: `picoclaw gateway -E` (allow empty config)
   - zeroclaw: `zeroclaw gateway` (auto-starts)
   - openclaw: `openclaw` (just run the binary)
   - ironclaw: `ironclaw run --no-onboard --cli-only`
   - nanobot: `nanobot gateway`
   - hermes-agent: `hermes`
   - nullclaw: `nullclaw gateway`
   - noclaw: N/A (not a daemon)

6. **Collect license** (from your dev machine, not the server):
   ```bash
   for REPO in nullclaw/nullclaw sipeed/picoclaw openagen/zeroclaw \
     HKUDS/nanobot openclaw/openclaw nearai/ironclaw NousResearch/hermes-agent; do
     echo "$REPO: $(gh api repos/$REPO --jq '.license.spdx_id')"
   done
   ```

7. **Update manifest.yml** with the new values and rebuild.

### Known issues

- **Empty subdomain bug**: The instance creation handler inserts `subdomain = ""`
  (line 357 of handlers_instances.rs), causing UNIQUE constraint failures on the
  second insert. Workaround: UPDATE the subdomain in SQLite after each create.

- **Warm pool ignores ram_mb**: Warm pool VMs are pre-booted with 2048 MB.
  The `ram_mb` parameter in the create request is stored in the DB but the actual
  VM already has its memory set. To test with different RAM, you need to bypass the
  warm pool (drain it first) or modify the Firecracker machine config directly.

- **Gateway startup requires config**: Most claws need an API key, database URL,
  or model config to start their gateway. Without these, the process exits
  immediately and RSS cannot be measured. The workaround flags (-E, --no-onboard,
  --allow-empty) work for picoclaw and zeroclaw but not for nanobot, hermes-agent,
  or ironclaw.
