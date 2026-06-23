//! Guard: every in-scope bootstrap/onboarding error-code literal emitted by the
//! producers that surface to the iPhone as `BootstrapError.serverError`
//! (`handlers_bootstrap.rs` + `handlers_sign_machine_cert.rs`, both decoded via
//! `BootstrapWire`) must come from `BootstrapErrorCode::X.as_str()` — never a raw
//! string literal. Unidirectional: a NEW raw literal fails the guard; the enum is
//! NOT required to be fully emitted (e.g. `engine_initializing` is engine-runtime).
//!
//! The pair-machine `StageError` codes (`stage_failed`, `no_transport_address`)
//! are a SEPARATE taxonomy intentionally not typed by `BootstrapErrorCode`; they
//! are the only allowed raw literals here, via a documented allowlist, so the
//! guard never breaks on that deliberate exclusion.

use std::fs;
use std::path::Path;

fn read(file: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read src/{file}: {e}"))
}

/// Raw string-literal codes passed as the 2nd argument of `cbor_error(` /
/// `claim_cbor_error(` (matched on the `StatusCode::…,  "literal"` shape, which
/// in these files appears only inside those error calls). A 2nd arg that is
/// `BootstrapErrorCode::X.as_str()` contributes nothing — only raw literals do.
fn raw_literal_codes(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(idx) = src[from..].find("cbor_error(") {
        let at = from + idx;
        from = at + "cbor_error(".len();
        // Char-boundary-safe: bound the search to this call's first `)` rather than
        // a fixed byte window (these files carry multibyte `──` box-drawing comments).
        let rest = &src[from..];
        let call = rest.find(')').map_or(rest, |p| &rest[..p]);
        let Some(sc) = call.find("StatusCode::") else {
            continue;
        };
        let after = &call[sc..];
        if let Some(comma) = after.find(',') {
            let arg = after[comma + 1..].trim_start();
            if let Some(stripped) = arg.strip_prefix('"') {
                if let Some(end) = stripped.find('"') {
                    out.push(stripped[..end].to_string());
                }
            }
        }
    }
    out
}

const IN_SCOPE_FILES: &[&str] = &["handlers_bootstrap.rs", "handlers_sign_machine_cert.rs"];

/// Codes from the `/bootstrap/pair-machine/local/stage` daemon/local-stage path.
/// These are a SEPARATE pair-machine local-stage taxonomy that does NOT surface
/// to the iPhone as `BootstrapError` (the local-stage client is the macOS daemon,
/// not a `BootstrapWire` consumer), so they are intentionally NOT typed by
/// `BootstrapErrorCode` and are the only raw error literals allowed in scope.
const PAIR_MACHINE_LOCAL_STAGE_ALLOWLIST: &[&str] = &[
    "household_already_paired",
    "invalid_request_body",
    "unsupported_transport",
    "no_transport_address",
    "stage_failed",
];

#[test]
fn no_raw_inscope_bootstrap_error_literal_bypasses_the_enum() {
    for file in IN_SCOPE_FILES {
        for code in raw_literal_codes(&read(file)) {
            assert!(
                PAIR_MACHINE_LOCAL_STAGE_ALLOWLIST.contains(&code.as_str()),
                "{file}: raw bootstrap error literal \"{code}\" passed to cbor_error — type it via \
                 BootstrapErrorCode::X.as_str() (or, for the pair-machine local-stage taxonomy, add \
                 it to the documented allowlist)"
            );
        }
    }
}

#[test]
fn handlers_type_their_bootstrap_errors_via_the_enum() {
    for file in IN_SCOPE_FILES {
        assert!(
            read(file).contains("BootstrapErrorCode::"),
            "{file} must emit its bootstrap error codes via BootstrapErrorCode"
        );
    }
}
