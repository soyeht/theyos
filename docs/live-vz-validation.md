# Live macOS VZ runner validation (opt-in) — runbook

Opt-in procedure for validating the macOS Virtualization.framework (VZ) runner
against **real** VMs. This is **P5 part A**: the harness exists and is
**default-skip**; **live VM execution is BLOCKED until separate authorization**.

> ⚠️ **Stop point.** Booting real VMs consumes the host's 2 admission slots,
> requires VZ entitlements and a prepared base image, and touches real local
> state. Do **not** run the VM-boot phases without explicit authorization and
> confirmed isolation. The shipping `/Applications/Soyeht.app` must remain
> untouched.

## Hard gate (default-skip)

Nothing runs against VZ unless **both** are true:

1. `THEYOS_LIVE_VZ=1` is exported, **and**
2. every stateful path points at an isolated scratch dir under a
   `live-vz-scratch` root (the harness refuses otherwise — fail-closed).

A normal `cargo test` (CI or local) never touches VZ.

## Prerequisites

- A real Apple-silicon Mac with Virtualization.framework entitlements.
- A prepared base image built **into the scratch dir** via
  `theyos init-macos-guest` (never the default/shipping location).
- The runner binary built from this branch.
- No shipping VM workload running that would contend for the 2 slots; use an
  isolated dev engine if an engine is required — never the shipping app.

## Isolation (required for any live run)

Point every stateful path at a scratch root and nothing else:

```bash
export THEYOS_LIVE_VZ=1
export SCRATCH=/tmp/live-vz-scratch
export THEYOS_VM_VMS_PATH="$SCRATCH/vms"
export THEYOS_VM_STATE_DIR="$SCRATCH/state"
export THEYOS_SNAPSHOTS_DIR="$SCRATCH/snapshots"
export THEYOS_VM_ASSETS_DIR="$SCRATCH/assets"
mkdir -p "$THEYOS_VM_VMS_PATH" "$THEYOS_VM_STATE_DIR" "$THEYOS_SNAPSHOTS_DIR" "$THEYOS_VM_ASSETS_DIR"
```

The harness asserts each path is absolute, contains `live-vz-scratch`, and is
**not** inside `Soyeht.app` / `Soyeht Dev.app`. If any check fails it panics
before doing anything (fail-closed).

## Phase 1 — isolation precheck (SAFE, no VM boot)

This runs only the scratch-dir verification (create + writability probe). It does
**not** boot VMs, consume slots, or touch real state:

```bash
cargo test -p vmrunner-macos-rs --test live_vz_validation -- --ignored live_isolation_precheck
```

Expected: `isolation precheck OK: 4 scratch dirs verified.`

## Phase 2 — VM-boot validation (AUTHORIZED-MANUAL, real VZ — BLOCKED by default)

> Run only after explicit authorization. Each step boots real VMs in the scratch
> environment. Confirm isolation (Phase 1 green) first.

What it validates (and the expected fail-closed behavior):

1. **Admission limit** — create 3 instances; the 3rd is refused with
   `HostVmLimitReached` (`MACOS_VM_LIMIT = 2`); no 3rd VM starts.
2. **Warm-pool boot** — a warm-pool VM boots from the scratch snapshot; the slot
   is accounted; draining releases it.
3. **Disk-space gate** — with the scratch volume below the 5 GB threshold, a
   warm-pool clone is refused **before** `cp -c` (P4 gate), the lease is released
   cleanly, and no VM starts.
4. **Stop/release discipline** — a clean stop releases the slot; a failed/unclean
   stop retains the lease (slot held until reboot).

Detailed steps (init base image into `$SCRATCH`, start the runner with the
isolated env, drive `Create` / `WarmPoolRefill` over IPC, assert the above) are
performed manually under supervision; do not script an unattended live run.

## Log collection (sanitized only)

Collect the runner's stderr/`tracing` output. **Sanitize before sharing**: use
only neutral aliases (`mac-alpha`, `device-alpha`) and documentation-safe
addresses (`192.0.2.10`, `198.51.100.10`). Never include real machine/account
names, SSH hostnames, LAN/tailnet IPs, or other personal identifiers (see the
repo privacy rules). Strip them with your own ignored local mapping; never commit
real values.

## Safety / stop points

- If any step would touch real/default state (paths missing the `live-vz-scratch`
  sentinel), **stop** — the harness already fails closed.
- Never quit, restart, or contend with the shipping `/Applications/Soyeht.app`.
- Booting real VMs, consuming the 2 slots, using a real base image, or using the
  Dev engine/app all require **separate authorization** — stop and report the
  plan first.
