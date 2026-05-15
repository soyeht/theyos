//! Warm boot performance benchmark for snapshot restore.
//!
//! Measures the time from snapshot restore request to claw being ready.
//! Target: <2s (NFR-002)
//!
//! To run:
//!
//! ```bash
//! cargo bench --bench warm_boot -- --sample-size 50
//! ```
//!
//! **Note**: This benchmark requires real VZ Framework and is macOS-only.

#![cfg(target_os = "macos")]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![allow(clippy::uninlined_format_args)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::time::Duration;

// Note: These benchmarks are stubs for the MVP implementation
// Real benchmarks would:
// 1. Have a pre-created snapshot file
// 2. Measure time from restore request to VM ready
// 3. Verify VM is actually running (not just restored)

fn benchmark_warm_boot(c: &mut Criterion) {
    let mut group = c.benchmark_group("vm_warm_boot");

    group.sample_size(50); // Warm boot is fast, can do more samples

    // Benchmark with different snapshot sizes
    for snapshot_size_mb in [100, 500, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new(format!("snapshot_{}MB", snapshot_size_mb), snapshot_size_mb),
            snapshot_size_mb,
            |b, size| {
                b.iter(|| {
                    // Stub: Simulate snapshot restore
                    // Real implementation:
                    // 1. Create VZVirtualMachine
                    // 2. Call restore(snapshot_path)
                    // 3. Wait for VM state == Running
                    // 4. Verify claw HTTP responds

                    let snapshot_path = get_snapshot_path(*size);
                    let vm = create_vm_for_restore();
                    restore_from_snapshot(black_box(&vm), black_box(&snapshot_path));

                    // Simulate restore time (remove in real implementation)
                    std::thread::sleep(Duration::from_millis(10));
                })
            },
        );
    }

    group.measurement_time(Duration::from_secs(30));
    group.finish();
}

fn benchmark_snapshot_save(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_save");

    group.bench_function("save_100mb_state", |b| {
        b.iter(|| {
            // Stub: Simulate snapshot save
            // Real implementation:
            // 1. Create and start VM
            // 2. Run some workload (100MB memory)
            // 3. Call pause(snapshot_path)
            // 4. Measure time to save

            let vm = create_and_start_vm();
            let snapshot_path = std::path::PathBuf::from("/tmp/test_snapshot.vzsnapshot");
            save_snapshot(black_box(&vm), black_box(&snapshot_path));

            // Simulate save time (remove in real implementation)
            std::thread::sleep(Duration::from_millis(50));
        })
    });

    group.finish();
}

fn benchmark_warm_pool_take(c: &mut Criterion) {
    let mut group = c.benchmark_group("warm_pool");

    group.bench_function("take_from_pool", |b| {
        b.iter(|| {
            // Benchmark taking a pre-warmed VM from the pool
            // This should be faster than cold boot

            let vm = take_from_warm_pool();
            black_box(vm);
        })
    });

    group.bench_function("warm_vs_cold", |b| {
        b.iter(|| {
            // Compare warm boot vs cold boot
            // Warm boot should be <2s, cold boot <20s

            let start = std::time::Instant::now();
            let vm = take_from_warm_pool();
            let warm_time = start.elapsed();

            let start = std::time::Instant::now();
            let vm2 = create_vm_cold();
            let cold_time = start.elapsed();

            // Assert warm is at least 10x faster
            assert!(warm_time.as_secs_f64() < cold_time.as_secs_f64() / 10.0);

            black_box((vm, vm2));
        })
    });

    group.finish();
}

// Stub helper functions (replace with real implementations)

fn get_snapshot_path(size_mb: u32) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/tmp/snapshot_{}mb.vzsnapshot", size_mb))
}

struct VMHandle;

fn create_vm_for_restore() -> VMHandle {
    VMHandle
}

fn restore_from_snapshot(_vm: &VMHandle, _path: &std::path::Path) {
    // Stub: would call vm.restore(path)
}

fn create_and_start_vm() -> VMHandle {
    VMHandle
}

fn save_snapshot(_vm: &VMHandle, _path: &std::path::Path) {
    // Stub: would call vm.pause(path)
}

fn take_from_warm_pool() -> VMHandle {
    VMHandle
}

fn create_vm_cold() -> VMHandle {
    VMHandle
}

criterion_group!(
    benches,
    benchmark_warm_boot,
    benchmark_snapshot_save,
    benchmark_warm_pool_take
);
criterion_main!(benches);

#[cfg(test)]
mod tests {
    #[test]
    fn test_warm_boot_target() {
        // Verify warm boot meets <2s target

        // Real test would:
        // 1. Restore from snapshot
        // 2. Measure time to HTTP ready
        // 3. Assert time < 2s
    }

    #[test]
    fn test_warm_boot_vs_cold_boot() {
        // Verify warm boot is significantly faster

        // Real test would:
        // 1. Measure cold boot time
        // 2. Measure warm boot time
        // 3. Assert warm < cold / 10 (at least 10x faster)
    }

    #[test]
    fn test_snapshot_restore_consistency() {
        // Verify snapshot restore produces consistent results

        // Real test would:
        // 1. Create VM and set state
        // 2. Save snapshot
        // 3. Restore from snapshot
        // 4. Verify VM state matches saved state
    }
}
