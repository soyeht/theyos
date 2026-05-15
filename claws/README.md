# Claws

Orchestration layer for multi-tenant AI assistant instances.

## How it works

theyOS doesn't bundle upstream claw code. Instead:

1. **`manifest.yml`** defines all supported claw types (canonical source of truth)
2. **`scripts/setup.sh`** clones repos into `theyos/claws/src/`
3. **Admin backend + Firecracker runtime** creates isolated microVM instances in `theyos/claws/data/`

## Adding a new claw type

1. Add an entry to `manifest.yml` with the repo URL and branch
2. Run `scripts/setup.sh` to clone it
3. Ensure the claw source/binary bootstrap is supported in the installer plan

## Scripts

- `claw-autoupdate` (Rust binary) — Git pull for claws with autoupdate enabled
  - Usage: `claw-autoupdate [--dry-run] [claw...]`
  - Build: `cd admin/rust && cargo build -p claw-autoupdate-rs`
- Customer lifecycle is managed by the admin API via Firecracker (`fc-agent-runtime.sh`)

## Customer data layout

```
theyos/claws/data/<claw-type>/customers/<name>/
├── config.json          # Instance configuration
├── workspace/           # Agent workspace files
└── autoupdate.json      # {"enabled": true} to opt in
```
