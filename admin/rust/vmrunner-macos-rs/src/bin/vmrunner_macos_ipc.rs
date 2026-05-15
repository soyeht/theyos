//! `vmrunner_macos_ipc` — JSON-RPC line-protocol IPC binary for macOS VM lifecycle.
//!
//! # Protocol
//!
//! One JSON object per line on stdin; one JSON response per line on stdout.
//!
//! Request:  `{"method": "Create", "params": { ... }}`
//! Response: `{"ok": true, "result": {...}}` or `{"ok": false, "error": "description"}`

// objc 0.2.7 uses the deprecated `cfg(cargo-clippy)` internally in its macros.
#![allow(unexpected_cfgs)]

// On macOS, include the full implementation.
// On other platforms, provide a stub that exits with an error.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)] // Required for Objective-C FFI via objc-rs
#[path = "vmrunner_macos_ipc_macos.rs"]
mod imp;

#[cfg(target_os = "macos")]
fn main() {
    imp::main_impl();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("vmrunner_macos_ipc requires macOS with Apple Virtualization Framework");
    std::process::exit(1);
}
