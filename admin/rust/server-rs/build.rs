//! Build script for server-rs.
//!
//! On macOS, generates Rust FFI bindings for Apple's `dns_sd.h` header
//! (the system mDNS bridge). The generated `bindings.rs` is included by
//! `bonjour_impl_dns_sd.rs` to publish and browse `_soyeht-household._tcp`
//! through `mDNSResponder` instead of racing it on UDP 5353 with the
//! pure-Rust `mdns-sd` crate.
//!
//! On other platforms this script is a no-op — the workspace's
//! `[target.'cfg(target_os = "macos")'.build-dependencies]` keeps the
//! `bindgen` build-dep itself out of the dep graph, so non-macOS builds
//! never compile bindgen.

fn main() {
    #[cfg(target_os = "macos")]
    macos::generate();
}

#[cfg(target_os = "macos")]
mod macos {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    pub fn generate() {
        let sdk_path = sdk_path();

        // We allowlist only the dns_sd / TXTRecord surface we use. Pulling
        // in the entire SDK header set would generate ~thousands of unused
        // declarations and slow the build.
        let bindings = bindgen::Builder::default()
            .header_contents("wrapper.h", "#include <dns_sd.h>")
            .clang_arg(format!("-isysroot{sdk_path}"))
            .allowlist_function("DNSService.*")
            .allowlist_function("TXTRecord.*")
            .allowlist_type("DNSService.*")
            .allowlist_type("TXTRecord.*")
            .allowlist_type("_DNSService.*")
            .allowlist_var("kDNSService.*")
            // Generate `extern "C"` blocks; the system framework provides
            // these symbols via the standard /usr/lib/libSystem.dylib link.
            .layout_tests(false)
            .derive_debug(true)
            .derive_default(false)
            // bindgen sometimes warns about doc-comments containing
            // backslashes; downgrade to silence.
            .clang_arg("-Wno-everything")
            .generate()
            .expect("bindgen failed to generate dns_sd bindings");

        let out_path: PathBuf = env::var("OUT_DIR").expect("OUT_DIR not set").into();
        bindings
            .write_to_file(out_path.join("dns_sd_bindings.rs"))
            .expect("failed to write dns_sd_bindings.rs");

        // Re-run when the SDK changes (e.g., Xcode update).
        println!("cargo:rerun-if-changed=build.rs");
        println!("cargo:rerun-if-env-changed=SDKROOT");
    }

    fn sdk_path() -> String {
        let output = Command::new("xcrun")
            .args(["--sdk", "macosx", "--show-sdk-path"])
            .output()
            .expect("xcrun --sdk macosx --show-sdk-path failed");
        assert!(
            output.status.success(),
            "xcrun --show-sdk-path returned status {}: stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("xcrun stdout not UTF-8")
            .trim()
            .to_string()
    }
}
