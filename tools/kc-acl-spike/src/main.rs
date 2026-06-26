//! THROWAWAY local spike for P0.3-C Tier 2: macOS login-keychain
//! generic-password ACL / Designated-Requirement durability across re-sign.
//!
//! This binary deliberately mirrors the engine's macOS path
//! (admin/rust/keystore-rs/src/macos_backend.rs): it uses the same
//! security-framework generic-password API, so the keychain item's ACL is
//! created exactly as the engine would create it. The READING binary's code
//! signature is what the keychain ACL gates, so the test must be performed by
//! THIS signed binary (not the `security` CLI).
//!
//! Safety invariants:
//! - Neutral service/account; a SYNTHETIC, non-secret marker value. Never a key.
//! - No real household material is touched. The companion runner cleans up.
//! - Output never dumps secret bytes (there are none); it prints a match flag.

use std::process::exit;

use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

const SERVICE: &str = "com.soyeht.theyos.acl-spike";
const ACCOUNT: &str = "probe";
/// Synthetic, non-secret marker. NOT key material.
const PROBE: &[u8] = b"acl-spike-probe-v1-not-a-secret";
/// Build marker baked at compile time. The runner sets KC_SPIKE_BUILD_TAG per
/// build so A and B get DISTINCT cdhashes while sharing the same signing
/// identity + identifier (i.e. the same Designated Requirement) - which is what
/// models a release re-sign. Printed below so it is never optimized away.
const BUILD_TAG: &str = match option_env!("KC_SPIKE_BUILD_TAG") {
    Some(tag) => tag,
    None => "dev",
};

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    match cmd.as_str() {
        "write" => match set_generic_password(SERVICE, ACCOUNT, PROBE) {
            Ok(()) => println!(
                "WRITE ok build_tag={BUILD_TAG} service={SERVICE} account={ACCOUNT} len={}",
                PROBE.len()
            ),
            Err(e) => {
                println!("WRITE err osstatus={}", e.code());
                exit(2);
            }
        },
        "read" => match get_generic_password(SERVICE, ACCOUNT) {
            Ok(bytes) => {
                let matches = bytes == PROBE;
                println!("READ ok build_tag={BUILD_TAG} len={} matches_probe={matches}", bytes.len());
                if !matches {
                    exit(3);
                }
            }
            Err(e) => {
                // -25308 errSecInteractionNotAllowed (no UI to prompt: headless deny)
                // -25244 errSecNoAccessForItem / -128 errUserCanceled also indicate
                // the ACL did not grant this binary access.
                println!("READ denied build_tag={BUILD_TAG} osstatus={}", e.code());
                exit(4);
            }
        },
        "delete" => match delete_generic_password(SERVICE, ACCOUNT) {
            Ok(()) => println!("DELETE ok"),
            // -25300 errSecItemNotFound: already gone -> success post-condition.
            Err(e) if e.code() == -25300 => println!("DELETE noop (not found)"),
            Err(e) => {
                println!("DELETE err osstatus={}", e.code());
                exit(5);
            }
        },
        _ => {
            eprintln!("usage: kc-acl-spike <write|read|delete>");
            exit(64);
        }
    }
}
