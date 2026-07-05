//! Build script for server-rs.
//!
//! On macOS, generates Rust FFI bindings for Apple's `dns_sd.h` header
//! (the system mDNS bridge). The generated `bindings.rs` is included by
//! `bonjour_impl_dns_sd.rs` to publish and browse `_soyeht-household._tcp`
//! through `mDNSResponder` instead of racing it on UDP 5353 with the
//! pure-Rust `mdns-sd` crate.
//!
//! On other platforms this script only emits build metadata — the workspace's
//! `[target.'cfg(target_os = "macos")'.build-dependencies]` keeps the
//! `bindgen` build-dep itself out of the dep graph, so non-macOS builds
//! never compile bindgen.

fn main() {
    emit_build_git_sha();

    #[cfg(target_os = "macos")]
    macos::generate();
}

fn emit_build_git_sha() {
    println!("cargo:rerun-if-env-changed=THEYOS_BUILD_GIT_SHA");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");

    let manifest_dir = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"),
    );
    if let Some(git_dir) = find_git_dir(&manifest_dir) {
        let head = git_dir.join("HEAD");
        println!("cargo:rerun-if-changed={}", head.display());
        println!(
            "cargo:rerun-if-changed={}",
            git_dir.join("packed-refs").display()
        );
        if let Ok(head_contents) = std::fs::read_to_string(&head) {
            if let Some(reference) = head_contents.trim().strip_prefix("ref: ") {
                println!(
                    "cargo:rerun-if-changed={}",
                    git_dir.join(reference).display()
                );
            }
        }
    }

    let sha = explicit_build_sha_override()
        .or_else(|| git_head_sha(&manifest_dir))
        .or_else(github_sha)
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=THEYOS_SERVER_BUILD_GIT_SHA={sha}");
}

fn explicit_build_sha_override() -> Option<String> {
    match std::env::var("THEYOS_BUILD_GIT_SHA") {
        Ok(value) if is_full_git_sha(&value) => Some(value),
        Ok(_) => panic!("THEYOS_BUILD_GIT_SHA must be a full 40-hex SHA"),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("THEYOS_BUILD_GIT_SHA must be valid Unicode")
        }
    }
}

fn github_sha() -> Option<String> {
    std::env::var("GITHUB_SHA")
        .ok()
        .filter(|value| is_full_git_sha(value))
}

fn git_head_sha(manifest_dir: &std::path::Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(manifest_dir)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8(output.stdout).ok()?.trim().to_string();
    is_full_git_sha(&sha).then_some(sha)
}

fn find_git_dir(start: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut current = Some(start);
    while let Some(path) = current {
        let candidate = path.join(".git");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if candidate.is_file() {
            if let Ok(contents) = std::fs::read_to_string(&candidate) {
                if let Some(path) = contents.trim().strip_prefix("gitdir: ") {
                    let git_dir = std::path::PathBuf::from(path);
                    return Some(if git_dir.is_absolute() {
                        git_dir
                    } else {
                        candidate.parent()?.join(git_dir)
                    });
                }
            }
        }
        current = path.parent();
    }
    None
}

fn is_full_git_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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
