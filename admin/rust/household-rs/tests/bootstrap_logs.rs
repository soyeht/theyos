use household_rs::bootstrap::{BootstrapOpts, KeyBackingPolicy, bootstrap_or_load, log_error};
use household_rs::keystore::hh_priv_account;
use tempfile::tempdir;
use tracing_test::traced_test;

fn opts() -> BootstrapOpts {
    BootstrapOpts {
        household_name: "Sample Home".into(),
        hostname_label: Some("studio-mac".into()),
    }
}

#[traced_test]
#[test]
fn fresh_bootstrap_emits_household_observable_stage_shape_and_timing() {
    let temp = tempdir().unwrap();
    let started = std::time::Instant::now();

    let loaded = bootstrap_or_load(temp.path(), opts(), KeyBackingPolicy::ForceSoftware).unwrap();

    assert_eq!(loaded.backing, "software");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(2_000),
        "household bootstrap exceeded SC-001 local budget"
    );

    // `bootstrap.endpoint.live`, `bonjour.published`, and `pair_device_window.opened`
    // are emitted by server-rs/install_cli.rs after household-rs returns.
    let observable = [
        "bootstrap.start",
        "bootstrap.key_gen.household",
        "bootstrap.key_gen.machine",
        "bootstrap.keystore.write",
        "bootstrap.persist.household_record",
        "bootstrap.persist.machine_cert",
        "bootstrap.complete",
    ];
    for stage in observable {
        assert!(logs_contain(stage), "missing log stage {stage}");
    }
    assert!(logs_contain("which=\"household\""));
    assert!(logs_contain("which=\"machine\""));

    logs_assert(|lines| {
        for stage in observable {
            let matching: Vec<_> = lines
                .iter()
                .copied()
                .filter(|line| line.contains(stage))
                .collect();
            if matching.is_empty() {
                return Err(format!("missing stage {stage}"));
            }
            for line in matching {
                if !line.contains("elapsed_ms") {
                    return Err(format!("{stage} missing elapsed_ms: {line}"));
                }
                if !line.contains("result") {
                    return Err(format!("{stage} missing result: {line}"));
                }
            }
        }
        Ok(())
    });
}

#[traced_test]
#[test]
fn idempotent_rerun_emits_single_skip_with_identity_fields() {
    let temp = tempdir().unwrap();

    let first = bootstrap_or_load(temp.path(), opts(), KeyBackingPolicy::ForceSoftware).unwrap();
    let second = bootstrap_or_load(temp.path(), opts(), KeyBackingPolicy::ForceSoftware).unwrap();

    assert_eq!(first.record.hh_id, second.record.hh_id);
    assert_eq!(first.record.created_at, second.record.created_at);

    logs_assert(|lines| {
        let skips: Vec<_> = lines
            .iter()
            .copied()
            .filter(|line| line.contains("bootstrap.skip"))
            .collect();
        if skips.len() != 1 {
            return Err(format!(
                "expected exactly one bootstrap.skip, got {}",
                skips.len()
            ));
        }
        let skip = skips[0];
        for expected in [
            first.record.hh_id.as_str(),
            first.record.name.as_str(),
            &first.record.created_at.to_string(),
        ] {
            if !skip.contains(expected) {
                return Err(format!("bootstrap.skip missing {expected}: {skip}"));
            }
        }
        Ok(())
    });
}

#[traced_test]
#[test]
fn keystore_failure_log_carries_structured_error_fields() {
    let temp = tempdir().unwrap();
    let loaded = bootstrap_or_load(temp.path(), opts(), KeyBackingPolicy::ForceSoftware).unwrap();
    let secret_path = temp
        .path()
        .join("household")
        .join("secrets")
        .join(format!("{}.bin", hh_priv_account(&loaded.record.hh_id)));
    std::fs::remove_file(&secret_path).unwrap();

    let Err(error) = bootstrap_or_load(temp.path(), opts(), KeyBackingPolicy::ForceSoftware) else {
        panic!("missing software key must fail");
    };
    log_error(&error);

    logs_assert(|lines| {
        let error_line = lines
            .iter()
            .copied()
            .find(|line| line.contains("bootstrap failed"))
            .ok_or_else(|| "missing bootstrap failed log line".to_string())?;
        for expected in [
            "ERROR",
            "error.stage",
            "keystore.read.household",
            "error.kind",
            "keystore.not_found",
            "error.hint",
        ] {
            if !error_line.contains(expected) {
                return Err(format!("error log missing {expected}: {error_line}"));
            }
        }
        Ok(())
    });
}
