//! `PORTS.md` is the human-facing port registry. This test pins the iOS-facing
//! engine ports documented there to the actual code constants, so the registry
//! cannot silently drift from the engine. Together with the iOS-side
//! `SoyehtInstallProfile` port test (which mirrors 8091 / 8892), both ends of the
//! stack agree on the same canonical engine ports.

use server_rs::household_bootstrap::DEFAULT_HOUSEHOLD_PORT;

const PORTS_MD: &str = include_str!("../../../../PORTS.md");

/// The engine ADMIN port, mirrored by iOS `SoyehtInstallProfile.adminPort`.
const ADMIN_PORT: u16 = 8892;

#[test]
fn ports_md_documents_the_household_engine_port() {
    let value = DEFAULT_HOUSEHOLD_PORT.to_string();
    let documented = PORTS_MD
        .lines()
        .any(|line| line.contains("THEYOS_HOUSEHOLD_PORT") && line.contains(&value));
    assert!(
        documented,
        "PORTS.md must document THEYOS_HOUSEHOLD_PORT = {DEFAULT_HOUSEHOLD_PORT} \
         (the household engine default, server_rs::household_bootstrap::DEFAULT_HOUSEHOLD_PORT)"
    );
}

#[test]
fn ports_md_documents_the_admin_port() {
    let value = ADMIN_PORT.to_string();
    let documented = PORTS_MD
        .lines()
        .any(|line| line.contains("ADMIN_PORT") && line.contains(&value));
    assert!(
        documented,
        "PORTS.md must document ADMIN_PORT = {ADMIN_PORT} (mirrored by iOS adminPort)"
    );
}

#[test]
fn household_engine_default_is_8091() {
    // Anchors the documented value; the iOS SoyehtInstallProfile.bootstrapPort
    // test asserts the same 8091 on the client side.
    assert_eq!(DEFAULT_HOUSEHOLD_PORT, 8091);
}
