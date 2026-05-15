//! Cold boot performance benchmark for VM creation.
//!
//! Measures the time from VM creation request to claw being ready.
//! Target: <20s (NFR-001)
//!
//! To run:
//!
//! ```bash
//! cargo bench --bench vm_boot -- --sample-size 10
//! ```
//!
//! **Note**: This benchmark requires real VZ Framework and is macOS-only.
//! It will be ignored on other platforms.

#![cfg(target_os = "macos")]
#![allow(dead_code)]
#![allow(clippy::semicolon_if_nothing_returned)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::time::Duration;

// Note: These benchmarks are stubs for the MVP implementation
// Real benchmarks would:
// 1. Create actual VZVirtualMachine instances
// 2. Measure time from creation to VM ready
// 3. Include kernel boot time
// 4. Include claw initialization time

fn benchmark_cold_boot(c: &mut Criterion) {
    let mut group = c.benchmark_group("vm_cold_boot");

    // Benchmark with different configurations
    for cpus in [1, 2, 4] {
        for memory_mb in [512, 2048, 4096] {
            group.bench_with_input(
                BenchmarkId::new(
                    format!("cpus_{cpus}_mem_{memory_mb}MB"),
                    format!("{cpus}-{memory_mb}"),
                ),
                &(cpus, memory_mb),
                |b, (cpus, memory_mb)| {
                    b.iter(|| {
                        // Stub: Simulate VM creation and boot
                        // Real implementation:
                        // 1. Create VZVirtualMachineConfiguration
                        // 2. Create VZVirtualMachine
                        // 3. Call start()
                        // 4. Wait for VM state == Running
                        // 5. Wait for claw HTTP to respond

                        let config = create_vm_config(*cpus, *memory_mb);
                        let vm = create_vm(black_box(&config));
                        start_vm(black_box(&vm));

                        // Simulate boot time (remove in real implementation)
                        std::thread::sleep(Duration::from_millis(100));
                    })
                },
            );
        }
    }

    group.sample_size(10); // VM creation is slow
    group.measurement_time(Duration::from_secs(60));
    group.finish();
}

fn benchmark_vm_creation_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("vm_creation_overhead");

    group.bench_function("config_build", |b| {
        b.iter(|| {
            // Benchmark VZVirtualMachineConfigurationBuilder::build()
            let config = build_config();
            black_box(config);
        })
    });

    group.bench_function("vm_instantiation", |b| {
        b.iter(|| {
            // Benchmark VZVirtualMachine::new()
            let config = build_config();
            let vm = create_vm(&config);
            black_box(vm);
        })
    });

    group.finish();
}

// Stub helper functions (replace with real implementations)

fn create_vm_config(cpus: u32, memory_mb: u32) -> VMConfig {
    VMConfig {
        cpus,
        memory_mb,
        kernel_path: "/usr/local/share/theyos/vms/vmlinuz-aarch64".into(),
        rootfs_path: "/usr/local/share/theyos/vms/rootfs.img".into(),
    }
}

struct VMConfig {
    cpus: u32,
    memory_mb: u32,
    kernel_path: std::path::PathBuf,
    rootfs_path: std::path::PathBuf,
}

fn build_config() -> VMConfig {
    create_vm_config(2, 2048)
}

fn create_vm(_config: &VMConfig) -> VMHandle {
    VMHandle
}

struct VMHandle;

fn start_vm(_vm: &VMHandle) {
    // Stub: would call vm.start() and wait for ready
}

criterion_group!(benches, benchmark_cold_boot, benchmark_vm_creation_overhead);
criterion_main!(benches);

#[cfg(test)]
mod tests {
    #[test]
    fn test_cold_boot_target() {
        // Verify cold boot meets <20s target

        // Real test would:
        // 1. Create VM
        // 2. Measure time to HTTP ready
        // 3. Assert time < 20s
    }

    #[test]
    fn test_cold_boot_consistency() {
        // Verify cold boot time is consistent across runs

        // Real test would:
        // 1. Run cold boot 10 times
        // 2. Calculate mean and std dev
        // 3. Assert std dev < 5s (reasonable variance)
    }
}
