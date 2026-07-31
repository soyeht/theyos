//! Library-mode `UniFFI` binding generator for the claw-share bridge.
//!
//! The published `uniffi-bindgen-swift` standalone tool the original
//! `build-xcframework.sh` referenced does not exist on crates.io — the
//! supported path for uniffi 0.28 is *library mode*: build the crate's
//! own bindgen binary (this file) and point it at the compiled static
//! archive.
//!
//! Only compiled when the `uniffi` feature is on (the binary needs the
//! `cli` feature on the `uniffi` crate). The rest of the workspace
//! continues to build without the bindgen toolchain.

fn main() {
    uniffi::uniffi_bindgen_main();
}
