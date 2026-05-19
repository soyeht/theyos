//! macOS-only end-to-end smoke tests for the `dns_sd.h` backend.
//!
//! Exercises the publisher → mDNSResponder → browser chain in a single
//! process: registers a service via `PublisherHandle`, opens a
//! `BrowserHandle` against the same regtype, and asserts that the
//! browse → resolve → getaddrinfo chain materialises a
//! `ResolvedService` with the expected TXT record and at least one
//! address.
//!
//! Two test variants:
//! - `dns_sd_publish_then_browse_round_trips` — basic chain smoke test
//!   (promoted from B-4 ignore'd unit tests).
//! - `dns_sd_enriched_txt_keys_round_trip` (T016b) — asserts that ALL
//!   FR-012/FR-013 TXT enrichment keys (`hh_name`, `owner_display_name`,
//!   `device_count`, `platform`, `bootstrap_state`, `host_label`) survive
//!   the full `dns_sd` publish → browse → resolve chain.
//!
//! Runs unconditionally on macOS as part of `cargo test` so the lock
//! against regression of either the chain logic or the teardown
//! ordering is in place from B-4 onward.

#![cfg(target_os = "macos")]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use server_rs::bonjour_impl_dns_sd::{
    BrowserHandle, PublisherHandle, ServiceSpec, ShutdownOutcome,
};

/// Registers a service over the `dns_sd.h` backend, opens a browser
/// against the same regtype, and asserts the chain
/// browse → resolve → getaddrinfo materialises the registration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_sd_publish_then_browse_round_trips() {
    // Per-run unique regtype suffix. Necessary because mDNSResponder is
    // a system-wide daemon — back-to-back test runs on the same Mac
    // (e.g. a developer iterating locally) can otherwise collide with
    // residual state from a previous run that hasn't fully unwound.
    // CI runners get fresh VMs so this is mostly local-dev hygiene.
    let pid = std::process::id();
    let regtype_owned = format!("_b4smoke-{pid:x}._tcp.local.");
    let regtype: &str = &regtype_owned;

    let publisher = PublisherHandle::new().expect("PublisherHandle::new");

    let mut txt = HashMap::new();
    txt.insert("hh_id".to_string(), "b4-smoke-hh".to_string());
    txt.insert("pair_nonce".to_string(), "b4-smoke-nonce".to_string());

    let spec = ServiceSpec {
        service_type: regtype,
        instance: "b4-smoke",
        host: "b4-smoke.local.",
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 8443,
        txt: &txt,
    };

    let fullname = publisher.register(&spec).expect("register");
    eprintln!("[bonjour_macos_smoke] registered fullname={fullname}");

    // Give mDNSResponder a moment to commit the registration before
    // we start browsing — without this the browser sometimes opens
    // its socket before the registration is visible.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let browser = BrowserHandle::new().expect("BrowserHandle::new");
    let stream = browser.browse(regtype).expect("browse");

    // 15 s budget: cold GitHub-hosted macOS runners pay tokio-scheduler
    // warmup + libdispatch wakeup before the first browse callback fires.
    // Local Mac finishes in ~10 ms; CI is the constraint.
    let resolved = tokio::time::timeout(Duration::from_secs(15), stream.next())
        .await
        .expect("did not receive a ResolvedService within 15s")
        .expect("stream closed without yielding a ResolvedService");

    eprintln!(
        "[bonjour_macos_smoke] resolved: type={} port={} addresses={:?}",
        resolved.service_type(),
        resolved.port(),
        resolved.addresses()
    );

    assert_eq!(resolved.service_type(), regtype);
    assert_eq!(resolved.txt("hh_id"), Some("b4-smoke-hh"));
    assert_eq!(resolved.txt("pair_nonce"), Some("b4-smoke-nonce"));
    assert!(
        !resolved.addresses().is_empty(),
        "expected at least one address in the resolved set"
    );
    assert_eq!(resolved.port(), 8443);

    // Clean shutdown of both ends — exercising the path that previously
    // SIGSEGV'd at process exit before the self-pipe / select rework.
    browser.shutdown();
    let outcome = publisher.shutdown_and_wait(Duration::from_secs(2)).await;
    eprintln!("[bonjour_macos_smoke] publisher shutdown outcome: {outcome:?}");
    assert!(matches!(outcome, ShutdownOutcome::Ok));
}

/// T016b — verify that ALL FR-012/FR-013 TXT enrichment keys survive the
/// full `dns_sd` publish → browse → resolve chain. This prevents future
/// regressions where a new key is added to `PublishParams` but silently
/// dropped by the `ServiceInfo` TXT encoding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_sd_enriched_txt_keys_round_trip() {
    let pid = std::process::id();
    let regtype_owned = format!("_b4enriched-{pid:x}._tcp.local.");
    let regtype: &str = &regtype_owned;

    let publisher = PublisherHandle::new().expect("PublisherHandle::new");

    // All FR-012/FR-013 enrichment keys.
    let mut txt = HashMap::new();
    txt.insert("hh_id".to_string(), "hh_enrichedsmoke".to_string());
    txt.insert("hh_name".to_string(), "Smoke Home".to_string());
    txt.insert("m_id".to_string(), "m_enrichedsmoke".to_string());
    txt.insert("host_label".to_string(), "Mac".to_string());
    txt.insert("owner_display_name".to_string(), "Owner".to_string());
    txt.insert("device_count".to_string(), "1".to_string());
    txt.insert("platform".to_string(), "macos".to_string());
    txt.insert("bootstrap_state".to_string(), "ready".to_string());
    txt.insert("version".to_string(), "0.1.8".to_string());
    txt.insert("proto".to_string(), "1".to_string());

    let spec = ServiceSpec {
        service_type: regtype,
        instance: "b4-enriched-smoke",
        host: "b4-enriched-smoke.local.",
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 8444,
        txt: &txt,
    };

    let fullname = publisher.register(&spec).expect("register");
    eprintln!("[bonjour_macos_smoke/enriched] registered fullname={fullname}");

    tokio::time::sleep(Duration::from_millis(500)).await;

    let browser = BrowserHandle::new().expect("BrowserHandle::new");
    let stream = browser.browse(regtype).expect("browse");

    let resolved = tokio::time::timeout(Duration::from_secs(15), stream.next())
        .await
        .expect("did not receive a ResolvedService within 15s")
        .expect("stream closed without yielding a ResolvedService");

    eprintln!(
        "[bonjour_macos_smoke/enriched] resolved: type={} port={} addresses={:?}",
        resolved.service_type(),
        resolved.port(),
        resolved.addresses()
    );

    // Assert all FR-012/FR-013 enrichment keys survive the chain.
    assert_eq!(resolved.txt("hh_name"), Some("Smoke Home"), "hh_name");
    assert_eq!(
        resolved.txt("owner_display_name"),
        Some("Owner"),
        "owner_display_name"
    );
    assert_eq!(resolved.txt("device_count"), Some("1"), "device_count");
    assert_eq!(resolved.txt("platform"), Some("macos"), "platform");
    assert_eq!(
        resolved.txt("bootstrap_state"),
        Some("ready"),
        "bootstrap_state"
    );
    assert_eq!(resolved.txt("host_label"), Some("Mac"), "host_label");
    assert_eq!(resolved.txt("version"), Some("0.1.8"), "version");
    assert_eq!(resolved.port(), 8444);

    browser.shutdown();
    let outcome = publisher.shutdown_and_wait(Duration::from_secs(2)).await;
    eprintln!("[bonjour_macos_smoke/enriched] publisher shutdown outcome: {outcome:?}");
    assert!(matches!(outcome, ShutdownOutcome::Ok));
}
