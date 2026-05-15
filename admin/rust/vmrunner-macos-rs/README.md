# vmrunner-macos-rs

macOS Virtualization Framework (VZ) backend for theyOS, implementing the `VmRunner` trait for native Apple Silicon support.

## Overview

This crate enables theyOS to run claw instances natively on macOS using Apple's Virtualization Framework, providing the same functionality as the Linux/Firecracker backend (`vmrunner-rs`) but adapted for macOS platform constraints and APIs.

## Platform Support

- **macOS**: 14 (Sonoma) or later
- **Architecture**: Apple Silicon only (arm64 - M1/M2/M3)
- **Privileges**: No admin/sudo required (unprivileged VZ)

## Key Features

- **VmRunner Trait Implementation**: Platform-agnostic VM lifecycle interface
- **VZVirtualMachine Wrapper**: Safe Rust FFI bindings to Objective-C VZ APIs
- **Warm Pool**: Pre-warmed VM snapshots for <2s instance creation
- **NAT Networking**: Unprivileged network isolation with port forwarding
- **Configuration**: YAML-based config with validation and hot-reload
- **Diagnostics**: Structured JSON logging, crash reporting, health endpoints

## Architecture

```
executor-rs
    ↓ (uses VmRunner trait)
vmrunner-macos-rs (this crate)
    ↓ (FFI via objc-rs)
Virtualization.framework (Apple system framework)
```

### Module Structure

- **lib.rs**: `VmRunnerMacOS` struct implementing `VmRunner` trait
- **vz.rs**: `VZVirtualMachine` wrapper with safe Rust API
- **config.rs**: VM configuration builder and YAML config loading
- **snapshot.rs**: Snapshot management for warm pool
- **network.rs**: NAT networking and port forwarding
- **warm_pool.rs**: Warm pool manager with TTL tracking
- **error.rs**: Error types with thiserror

## Development

### Building

```bash
cd admin/rust
cargo build --package vmrunner-macos-rs
```

### Running Tests

```bash
# Unit tests (with mocked VZ APIs)
cargo test --package vmrunner-macos-rs

# Contract tests (against VmRunner trait)
cargo test --package executor-rs --test vmrunner_contract

# E2E tests (requires real VZ VMs)
cargo test --package e2e-rs --test macos_picoclaw_e2e
```

### Code Quality

```bash
# Format
cargo fmt --package vmrunner-macos-rs

# Lint
cargo clippy --package vmrunner-macos-rs -D warnings
```

## Unsafe Rust

This crate uses `unsafe` blocks for FFI bindings to Objective-C APIs via objc-rs. All unsafe blocks are documented with safety invariants:

- Pointer validity checks before dereferencing
- Proper memory management of Objective-C objects
- Thread safety assertions for concurrent VM operations

See inline comments in `vz.rs` for detailed safety documentation.

## Configuration

Configuration is loaded from `~/.theyos/config.yaml`:

```yaml
vm_backend:
  backend: "vz"
  macos:
    vms_path: "/usr/local/share/theyos/vms"
    snapshots_path: "~/Library/Application Support/theyos/snapshots"
    default_memory_mb: 2048
    default_cpus: 2

warm_pool:
  enabled: true
  size: 2
  ttl_hours: 24
```

Validation errors include line numbers and usage examples (FR-028a).

## File Locations

| Type | Location |
|------|----------|
| VM disk images | `/usr/local/share/theyos/vms/` |
| Snapshots | `~/Library/Application Support/theyos/snapshots/` |
| Logs | `~/Library/Logs/theyos/` |
| Crash reports | `~/Library/Caches/theyos/crashes/` |
| Config | `~/.theyos/config.yaml` |

## Performance Targets

- **Cold boot**: <20s (VM creation → claw ready)
- **Warm boot**: <2s (snapshot resume → claw ready)
- **Base memory**: <200MB without claws
- **Virtualization overhead**: <15% vs Linux native

## Security

- **Sandbox**: macOS sandbox profile restricts filesystem and network access
- **Entitlements**: Minimal entitlements (`com.apple.security.virtualization`, `com.apple.security.network.client`)
- **Network isolation**: NAT prevents inter-claw communication
- **No privilege escalation**: All operations unprivileged

## Testing Coverage

Target: 80%+ coverage for vmrunner-macos-rs

Verify with:
```bash
cargo tarpaulin --package vmrunner-macos-rs --out Html
```

## License

Internal to theyOS project.

## See Also

- [Repository README](../../../README.md) — project overview and install/update guide
