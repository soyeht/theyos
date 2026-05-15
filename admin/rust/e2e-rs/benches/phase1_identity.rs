#[path = "../tests/phase1_helpers.rs"]
mod phase1_helpers;

use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn criterion_identity_endpoint(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let td = tempfile::tempdir().expect("tempdir");
    let identity = Arc::new(phase1_helpers::bootstrap_identity(
        td.path(),
        "Sample Home",
        "studio-mac",
    ));
    let app = phase1_helpers::identity_router(Some(identity));
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind(("127.0.0.1", 0)))
        .expect("bind loopback identity bench listener");
    let addr = listener.local_addr().expect("local addr");
    runtime.spawn(async move {
        axum::serve(listener, app).await.expect("serve identity");
    });

    let url = format!("http://{addr}/api/v1/household/identity");
    wait_until_ready(&url);
    assert_p95_under_100ms(&url);

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .build();
    c.bench_function("phase1_identity_get_loopback", |b| {
        b.iter(|| {
            let resp = agent.get(&url).call().expect("GET identity");
            black_box(resp.status());
            let body = resp.into_string().expect("identity body");
            black_box(body);
        });
    });
}

fn wait_until_ready(url: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(resp) = ureq::get(url).call() {
            if resp.status() == 200 {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("identity benchmark server did not become ready");
}

fn assert_p95_under_100ms(url: &str) {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .build();
    let mut samples = Vec::with_capacity(1_000);
    for _ in 0..1_000 {
        let start = Instant::now();
        let resp = agent.get(url).call().expect("GET identity for p95");
        assert_eq!(resp.status(), 200);
        let _body = resp.into_string().expect("identity body");
        samples.push(start.elapsed());
    }
    samples.sort_unstable();
    let p50 = percentile(&samples, 50);
    let p95 = percentile(&samples, 95);
    let p99 = percentile(&samples, 99);
    eprintln!(
        "phase1 identity latency: p50={}ms p95={}ms p99={}ms",
        p50.as_secs_f64() * 1_000.0,
        p95.as_secs_f64() * 1_000.0,
        p99.as_secs_f64() * 1_000.0
    );
    assert!(
        p95 < Duration::from_millis(100),
        "GET /api/v1/household/identity p95 must be < 100ms, got {p95:?}"
    );
}

fn percentile(samples: &[Duration], percentile: usize) -> Duration {
    assert!(!samples.is_empty());
    let idx = ((samples.len() * percentile).div_ceil(100)).saturating_sub(1);
    samples[idx.min(samples.len() - 1)]
}

criterion_group!(benches, criterion_identity_endpoint);
criterion_main!(benches);
