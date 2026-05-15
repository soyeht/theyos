mod phase1_helpers;

use household_rs::machine_cert::load_self_cert;
use household_rs::storage::{household_record_path, machine_cert_for, read_optional_cbor};

#[test]
fn on_disk_cbor_chain_verifies_and_single_byte_tamper_fails() {
    let td = tempfile::tempdir().unwrap();
    phase1_helpers::bootstrap_identity(td.path(), "Sample Home", "studio-mac");

    let record: household_rs::HouseholdRecord =
        read_optional_cbor(&household_record_path(td.path()))
            .unwrap()
            .unwrap();
    let cert: household_rs::MachineCert = load_self_cert(td.path()).unwrap().unwrap();
    household_rs::verify_loaded_chain(&record, &cert).unwrap();

    let cert_path = machine_cert_for(td.path(), &cert.m_id.to_string());
    for path in [household_record_path(td.path()), cert_path.clone()] {
        let original = std::fs::read(&path).unwrap();
        let mut tampered = original.clone();
        let idx = tampered.len() / 2;
        tampered[idx] ^= 0x01;
        std::fs::write(&path, &tampered).unwrap();
        let loaded_record: Result<Option<household_rs::HouseholdRecord>, _> =
            read_optional_cbor(&household_record_path(td.path()));
        let loaded_cert: Result<Option<household_rs::MachineCert>, _> = load_self_cert(td.path());
        let failed = match (loaded_record, loaded_cert) {
            (Ok(Some(record)), Ok(Some(cert))) => {
                household_rs::verify_loaded_chain(&record, &cert).is_err()
            }
            _ => true,
        };
        assert!(failed, "tampered {} still verified", path.display());
        std::fs::write(&path, original).unwrap();
    }
}
