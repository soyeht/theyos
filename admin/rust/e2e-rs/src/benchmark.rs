use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::client::{AdminClient, JobPhase};
use crate::runner::all_claw_types;

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub claw_type: String,
    pub name: String,
    pub status: String,
    pub wall_clock_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_time_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub golden_image_used: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_skipped: Option<bool>,
    pub phases: Vec<JobPhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkSummary {
    pub timestamp: String,
    pub claws: BTreeMap<String, BenchmarkResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<Statistics>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Statistics {
    pub p50_seconds: f64,
    pub p95_seconds: f64,
    pub min_seconds: f64,
    pub max_seconds: f64,
    pub completed: usize,
    pub total_tested: usize,
}

pub struct BenchmarkConfig {
    pub timeout: Duration,
    pub poll_interval: Duration,
    pub settle: Duration,
    pub output: Option<PathBuf>,
    pub baseline: Option<PathBuf>,
}

#[must_use]
pub fn run_benchmark(
    client: &AdminClient,
    claw_types: &[&str],
    config: &BenchmarkConfig,
) -> BenchmarkSummary {
    let timestamp = now_iso();
    let mut claws = BTreeMap::new();

    eprintln!("============================================");
    eprintln!(" theyOS Claw Creation Benchmark");
    eprintln!("============================================");
    eprintln!();
    eprintln!("Timestamp: {timestamp}");
    eprintln!("Claw types: {}", claw_types.join(", "));
    eprintln!();

    for (i, ct) in claw_types.iter().enumerate() {
        if i > 0 {
            eprintln!("Settling {}s...", config.settle.as_secs());
            std::thread::sleep(config.settle);
        }
        let result = benchmark_one(client, ct, config);
        claws.insert(ct.to_string(), result);
    }

    let stats = compute_statistics(&claws);

    let summary = BenchmarkSummary {
        timestamp,
        claws,
        summary: stats,
    };

    print_summary_table(&summary, config.baseline.as_ref());

    if let Some(ref path) = config.output {
        match serde_json::to_string_pretty(&summary) {
            Ok(json) => match std::fs::write(path, &json) {
                Ok(()) => eprintln!("\nResults saved to: {}", path.display()),
                Err(e) => eprintln!("\nFailed to write results: {e}"),
            },
            Err(e) => eprintln!("\nFailed to serialize results: {e}"),
        }
    }

    summary
}

#[allow(clippy::too_many_lines)]
fn benchmark_one(
    client: &AdminClient,
    claw_type: &str,
    config: &BenchmarkConfig,
) -> BenchmarkResult {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let name = format!("bench-{claw_type}-{ts}");

    eprintln!(">>> Benchmarking: {claw_type}");
    eprintln!("    Name: {name}");

    let start = Instant::now();

    let (job_id, instance_id) = match client.create_instance(&name, claw_type, None) {
        Ok(cr) => {
            let iid = cr
                .instance
                .as_ref()
                .map(|i| i.id.clone())
                .unwrap_or_default();
            (cr.job_id, iid)
        }
        Err(e) => {
            #[allow(clippy::cast_possible_truncation)]
            // NOTE: elapsed ms fits in u64 for any realistic benchmark duration
            let wall = start.elapsed().as_millis() as u64;
            eprintln!("    ERROR: create failed: {e}");
            return BenchmarkResult {
                claw_type: claw_type.to_string(),
                name,
                status: "failed".to_string(),
                wall_clock_ms: wall,
                vm_time_ms: None,
                golden_image_used: None,
                install_skipped: None,
                phases: vec![],
                error: Some(format!("{e}")),
            };
        }
    };

    eprintln!("    Job ID: {job_id}");

    // Poll with configurable interval
    let poll_result = client.poll_job_interval(
        &job_id,
        config.timeout,
        &format!("bench-{claw_type}"),
        config.poll_interval,
    );

    #[allow(clippy::cast_possible_truncation)]
    // NOTE: elapsed ms fits in u64 for any realistic benchmark duration
    let wall = start.elapsed().as_millis() as u64;

    let result = match poll_result {
        Ok((_job_item, job_result)) => {
            eprintln!("    Total time: {wall}ms (~{}s)", wall / 1000);
            if let Some(vm_ms) = job_result.total_ms {
                eprintln!("    VM time:    {vm_ms}ms");
            }
            eprintln!(
                "    Golden img: {}",
                job_result.golden_image_used.unwrap_or(false)
            );
            eprintln!(
                "    Install skip: {}",
                job_result.install_skipped.unwrap_or(false)
            );
            eprintln!("    Status:     completed");

            BenchmarkResult {
                claw_type: claw_type.to_string(),
                name,
                status: "completed".to_string(),
                wall_clock_ms: wall,
                vm_time_ms: job_result.total_ms,
                golden_image_used: job_result.golden_image_used,
                install_skipped: job_result.install_skipped,
                phases: job_result.phases,
                error: None,
            }
        }
        Err(crate::error::E2eError::JobTimeout { elapsed_secs, .. }) => {
            eprintln!("    TIMEOUT after {elapsed_secs}s");
            BenchmarkResult {
                claw_type: claw_type.to_string(),
                name,
                status: "timeout".to_string(),
                wall_clock_ms: wall,
                vm_time_ms: None,
                golden_image_used: None,
                install_skipped: None,
                phases: vec![],
                error: Some(format!("timeout after {elapsed_secs}s")),
            }
        }
        Err(e) => {
            eprintln!("    FAILED: {e}");
            BenchmarkResult {
                claw_type: claw_type.to_string(),
                name,
                status: "failed".to_string(),
                wall_clock_ms: wall,
                vm_time_ms: None,
                golden_image_used: None,
                install_skipped: None,
                phases: vec![],
                error: Some(format!("{e}")),
            }
        }
    };

    // Always delete — fixes leak bug from the bash scripts
    eprintln!("    Cleaning up...");
    if !instance_id.is_empty() {
        let _ = client.delete_instance(&instance_id);
    }

    result
}

#[allow(clippy::cast_precision_loss)] // NOTE: wall_clock_ms is timing data; f64 precision is sufficient
fn compute_statistics(claws: &BTreeMap<String, BenchmarkResult>) -> Option<Statistics> {
    let mut times: Vec<f64> = claws
        .values()
        .filter(|r| r.status == "completed")
        .map(|r| r.wall_clock_ms as f64 / 1000.0)
        .collect();

    if times.is_empty() {
        return None;
    }

    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = times.len();

    let p50 = percentile(&times, 50.0);
    let p95 = percentile(&times, 95.0);

    Some(Statistics {
        p50_seconds: round2(p50),
        p95_seconds: round2(p95),
        min_seconds: round2(times[0]),
        max_seconds: round2(times[n - 1]),
        completed: n,
        total_tested: claws.len(),
    })
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
// NOTE: percentile arithmetic on small Vec lengths; precision/sign loss is acceptable
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.len() == 1 {
        return sorted[0];
    }
    let idx = (p / 100.0) * (sorted.len() - 1) as f64;
    let lo = idx.floor() as usize;
    let hi = idx.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        let frac = idx - lo as f64;
        sorted[lo] * (1.0 - frac) + sorted[hi] * frac
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[allow(clippy::cast_precision_loss, clippy::cast_possible_wrap)]
// NOTE: timing values in ms/f64 and timestamp arithmetic; precision loss is acceptable
fn print_summary_table(summary: &BenchmarkSummary, baseline_path: Option<&PathBuf>) {
    let baseline: Option<BenchmarkSummary> = baseline_path.and_then(|p| {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    });

    eprintln!();
    eprintln!("============================================");
    eprintln!(" Summary");
    eprintln!("============================================");
    eprintln!();

    let has_baseline = baseline.is_some();
    if has_baseline {
        eprintln!(
            "{:<12} {:>8} {:>8} {:>8} {:>8} {:>7} {:>5}",
            "Claw", "Time", "VM Boot", "Baseline", "Delta", "Golden", "Skip"
        );
        eprintln!(
            "{} {} {} {} {} {} {}",
            "-".repeat(12),
            "-".repeat(8),
            "-".repeat(8),
            "-".repeat(8),
            "-".repeat(8),
            "-".repeat(7),
            "-".repeat(5)
        );
    } else {
        eprintln!(
            "{:<12} {:>8} {:>8} {:>7} {:>5}  Status",
            "Claw", "Time", "VM Boot", "Golden", "Skip"
        );
        eprintln!(
            "{} {} {} {} {}  {}",
            "-".repeat(12),
            "-".repeat(8),
            "-".repeat(8),
            "-".repeat(7),
            "-".repeat(5),
            "-".repeat(10)
        );
    }

    for ct in &all_claw_types() {
        if let Some(r) = summary.claws.get(*ct) {
            let total_s = r.wall_clock_ms as f64 / 1000.0;
            let vm_s = r
                .vm_time_ms
                .map_or_else(|| "-".into(), |ms| format!("{:.1}s", ms as f64 / 1000.0));
            let golden = if r.golden_image_used.unwrap_or(false) {
                "Yes"
            } else {
                "No"
            };
            let skip = if r.install_skipped.unwrap_or(false) {
                "Yes"
            } else {
                "No"
            };
            let status_suffix = if r.status == "completed" {
                String::new()
            } else {
                format!(" [{}]", r.status)
            };

            if has_baseline {
                let base_ref = baseline.as_ref().unwrap();
                let (base_str, delta_str) = match base_ref.claws.get(*ct) {
                    Some(br) if br.status == "completed" => {
                        let bs = br.wall_clock_ms as f64 / 1000.0;
                        let d = total_s - bs;
                        (format!("{bs:.1}s"), format!("{d:+.1}s"))
                    }
                    _ => ("N/A".into(), "N/A".into()),
                };
                eprintln!(
                    "{ct:<12} {total_s:>7.1}s {vm_s:>8} {base_str:>8} {delta_str:>8} {golden:>7} {skip:>5}{status_suffix}"
                );
            } else {
                eprintln!(
                    "{:<12} {:>7.1}s {:>8} {:>7} {:>5}  {}{}",
                    ct, total_s, vm_s, golden, skip, r.status, status_suffix
                );
            }
        }
    }

    if let Some(ref stats) = summary.summary {
        eprintln!();
        eprintln!("Completed: {}/{}", stats.completed, stats.total_tested);
        eprintln!("p50: {:.1}s", stats.p50_seconds);
        eprintln!("p95: {:.1}s", stats.p95_seconds);
        eprintln!("min: {:.1}s", stats.min_seconds);
        eprintln!("max: {:.1}s", stats.max_seconds);
    }
}

fn now_iso() -> String {
    core_rs::time::now_iso_secs()
}
