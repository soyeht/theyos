mod phase1_helpers;

use household_rs::machine_cert::load_self_cert;

#[test]
fn machine_cert_hostname_is_bootstrap_snapshot() {
    let td = tempfile::tempdir().expect("tempdir");

    let first = phase1_helpers::bootstrap_identity(td.path(), "Sample Home", "studio-mac");
    let persisted_first: household_rs::MachineCert = load_self_cert(td.path())
        .expect("read first cert")
        .expect("first cert exists");
    assert_eq!(persisted_first.hostname, "studio-mac");

    let second = household_rs::bootstrap_or_load(
        td.path(),
        household_rs::BootstrapOpts {
            household_name: "Sample Home".to_string(),
            hostname_label: Some("studio-mac-renamed".to_string()),
        },
        household_rs::KeyBackingPolicy::ForceSoftware,
    )
    .expect("idempotent rerun");
    let persisted_second: household_rs::MachineCert = load_self_cert(td.path())
        .expect("read second cert")
        .expect("second cert exists");

    assert_eq!(first.record.hh_id, second.record.hh_id);
    assert_eq!(first.cert.m_id, second.cert.m_id);
    assert_eq!(persisted_second.hostname, "studio-mac");
    assert_eq!(persisted_first, persisted_second);
}
