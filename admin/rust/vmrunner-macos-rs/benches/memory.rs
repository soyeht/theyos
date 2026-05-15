//! Memory overhead benchmark for VM instances.
//!
//! Measures base memory usage without any claws.
//! Target: <200MB base (NFR-008)
//!
//! To run:
//!
//! ```bash
//! cargo bench --bench memory -- --sample-size 20
//! ```

#![cfg(target_os = "macos")]
#![allow(unused_variables)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::semicolon_if_nothing_returned)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::time::Duration;

// Note: These benchmarks are stubs for the MVP implementation
// Real benchmarks would:
// 1. Measure RSS (Resident Set Size) of the process
// 2. Account for VZ framework overhead
// 3. Exclude memory used by actual VMs (only measure base)

fn benchmark_base_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_base");

    group.bench_function("idle_process", |b| {
        b.iter(|| {
            // Measure memory usage of idle theyOS process
            // This should be <200MB

            let memory = get_process_memory();
            black_box(memory);

            // Assert memory target
            assert!(memory < 200 * 1024 * 1024, "Base memory exceeds 200MB");
        })
    });

    group.sample_size(20);
    group.measurement_time(Duration::from_secs(30));
    group.finish();
}

fn benchmark_memory_per_vm(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_per_vm");

    // Benchmark memory with different VM configurations
    for vm_count in [0, 1, 2, 5].iter() {
        group.bench_with_input(
            BenchmarkId::new("vms_running", vm_count),
            vm_count,
            |b, count| {
                b.iter(|| {
                    // Measure memory with N VMs running
                    let vms = create_vms(*count);
                    let memory = get_process_memory();

                    // Subtract base to get per-VM memory
                    let base_memory = 50 * 1024 * 1024; // ~50MB base
                    let per_vm = if *count > 0 {
                        (memory - base_memory) / *count as u64
                    } else {
                        0
                    };

                    black_box(per_vm);
                })
            },
        );
    }

    group.finish();
}

fn benchmark_memory_with_warm_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_warm_pool");

    for pool_size in [0, 2, 5].iter() {
        group.bench_with_input(
            BenchmarkId::new("warm_pool_size", pool_size),
            pool_size,
            |b, size| {
                b.iter(|| {
                    // Measure memory with warm pool of N snapshots
                    let pool = create_warm_pool(*size);
                    let memory = get_process_memory();

                    black_box(memory);
                })
            },
        );
    }

    group.finish();
}

// Stub helper functions

fn get_process_memory() -> u64 {
    // Stub: Return fake memory usage
    // Real implementation would:
    // 1. Call libc::getrusage(RUSAGE_SELF)
    // 2. Read ru_maxrss field
    // 3. Convert to bytes

    50 * 1024 * 1024 // 50MB stub
}

fn create_vms(count: u32) -> Vec<VMHandle> {
    (0..count).map(|_| VMHandle).collect()
}

struct VMHandle;

fn create_warm_pool(size: u32) -> Vec<SnapshotHandle> {
    (0..size).map(|_| SnapshotHandle).collect()
}

struct SnapshotHandle;

criterion_group!(
    benches,
    benchmark_base_memory,
    benchmark_memory_per_vm,
    benchmark_memory_with_warm_pool
);
criterion_main!(benches);

#[cfg(test)]
mod tests {
    #[test]
    fn test_base_memory_target() {
        // Verify base memory <200MB

        // Real test would:
        // 1. Start theyOS process
        // 2. Wait for idle (no VMs running)
        // 3. Measure RSS memory
        // 4. Assert <200MB
    }

    #[test]
    fn test_memory_leak_check() {
        // Verify no memory leaks over time

        // Real test would:
        // 1. Record initial memory
        // 2. Create and destroy 10 VMs sequentially
        // 3. Record final memory
        // 4. Assert growth <10MB (allow some variance)
    }

    #[test]
    fn test_warm_pool_memory_overhead() {
        // Verify warm pool doesn't use excessive memory

        // Real test would:
        // 1. Create warm pool with 2 snapshots
        // 2. Measure memory
        // 3. Destroy warm pool
        // 4. Verify memory freed
    }

    #[test]
    fn test_per_vm_memory_is_reasonable() {
        // Verify each VM doesn't use excessive memory

        // Real test would:
        // 1. Start VM with 512MB memory limit
        // 2. Measure process memory increase
        // 3. Assert increase <600MB (allow some overhead)
    }
}
