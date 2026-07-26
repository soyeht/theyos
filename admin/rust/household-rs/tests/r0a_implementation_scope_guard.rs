use std::fs;
use std::path::{Path, PathBuf};

fn package_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_workspace() -> PathBuf {
    package_dir()
        .parent()
        .expect("household-rs is a workspace child")
        .to_path_buf()
}

fn repository_root() -> PathBuf {
    rust_workspace()
        .parent()
        .and_then(Path::parent)
        .expect("admin/rust is below the repository root")
        .to_path_buf()
}

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path).expect("scope-guard source is UTF-8")
}

fn code_only(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn r0a_n_paths_are_limited_and_registered() {
    let lib = read(package_dir().join("src/lib.rs"));
    assert!(lib.contains("pub mod caveat_narrowing;"));
    assert!(lib.contains("pub mod caveats;"));
    assert!(!lib.contains("pub use caveat_narrowing"));
    assert!(!lib.contains("caveat_narrowing::*"));

    for absent in [
        "src/device_cert.rs",
        "src/household_mesh_peer_admission_store.rs",
        "src/owner_mesh_peer_admission.rs",
        "src/live_snapshot.rs",
        "src/owner_mesh_narrowing.rs",
        "src/caveat_narrowing_store.rs",
    ] {
        assert!(
            !package_dir().join(absent).exists(),
            "C/S/A or an alternate N module must stay out of Fatia N: {absent}"
        );
    }
}

#[test]
fn r0a_n_sources_stay_closed_and_effect_free() {
    let caveats = read(package_dir().join("src/caveats.rs"));
    let narrowing = read(package_dir().join("src/caveat_narrowing.rs"));
    let narrowing_code = code_only(&narrowing);
    let production_code = [code_only(&caveats), narrowing_code.clone()].join("\n");

    assert!(caveats.contains("HouseholdAddDevice"));
    assert!(caveats.contains("ConstraintValue"));
    assert!(caveats.contains("pub struct Constraints"));
    assert!(!caveats.contains("ConstraintValue::None"));
    assert!(!caveats.contains("BTreeMap<String, Vec<String>>"));
    assert!(narrowing_code.contains("DeviceCaveatNarrowingProofV1"));
    assert!(narrowing_code.contains("verify_explicit_household_add_device_grant"));
    let proof_offset = narrowing_code
        .find("pub struct DeviceCaveatNarrowingProofV1")
        .expect("opaque proof declaration");
    let preceding_line = narrowing_code[..proof_offset]
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .expect("declaration has preceding source");
    assert!(
        !preceding_line.trim().ends_with(")]"),
        "opaque proof must not carry a derive attribute"
    );
    assert!(!narrowing_code.contains("impl Clone for DeviceCaveatNarrowingProofV1"));
    assert!(!narrowing_code.contains("impl Copy for DeviceCaveatNarrowingProofV1"));
    assert!(!narrowing_code.contains("impl Default for DeviceCaveatNarrowingProofV1"));
    assert!(!narrowing_code.contains("impl Serialize for DeviceCaveatNarrowingProofV1"));
    assert!(!narrowing_code.contains("impl Deserialize for DeviceCaveatNarrowingProofV1"));
    assert!(!narrowing_code.contains("pub fn new("));
    assert!(!narrowing_code.contains("permits("));
    assert!(!narrowing_code.contains("owner_caveats("));
    assert!(!narrowing_code.contains("owner_capability_names("));

    for forbidden in [
        ["Product ", "A"].concat(),
        ["product", "_a"].concat(),
        ["product", "-a"].concat(),
        ["n", "vpn"].concat(),
        ["10.", "44."].concat(),
        ["Claw", "ShareBridge"].concat(),
        ["Ip", "Tunnel"].concat(),
        ["ip", "_tunnel"].concat(),
        ["Relay", "Stream"].concat(),
        ["Claw", "Vpn"].concat(),
        ["Network", "Settings"].concat(),
        ["Mesh", "LogStore"].concat(),
        ["Projected", "State"].concat(),
        ["device", "_cert"].concat(),
        ["owner", "_mesh_admission"].concat(),
        ["household", "_mesh_peer_admission"].concat(),
        ["std", "::net"].concat(),
        ["tokio", "::"].concat(),
        ["Command", "::new"].concat(),
        ["Tcp", "Listener"].concat(),
        ["ure", "q"].concat(),
        ["req", "west"].concat(),
    ] {
        assert!(
            !production_code.contains(&forbidden),
            "Fatia N contains a forbidden effect/boundary marker: {forbidden}"
        );
    }
}

#[test]
fn r0a_n_ratchet_names_new_targets() {
    let ratchet_path = ["owner_mesh_", "rendezvous_codec.rs"].concat();
    let r1a7 = read(package_dir().join("tests").join(ratchet_path));
    for needle in [
        "assert_eq!(targets.len(), 197",
        "filter(|target| target.kind == \"test\")",
        "146 + 2",
        "name == \"caveat_narrowing\"",
        "path == \"household-rs/tests/caveat_narrowing.rs\"",
        "name == \"r0a_implementation_scope_guard\"",
        "path == \"household-rs/tests/r0a_implementation_scope_guard.rs\"",
    ] {
        assert!(r1a7.contains(needle), "R1a.7 is missing `{needle}`");
    }

    let tsv = repository_root()
        .join("admin/contracts/mobile-claw-vpn/v1/owner_present_phase0_artifact_boundary_v1.tsv");
    assert!(
        tsv.is_file(),
        "TSV path must exist and stay byte-intact in Fatia N"
    );
}
