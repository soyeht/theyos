//! Resolve the emoji-security-code wordlist CSV path at build time.
//!
//! The CSV lives at `admin/rust/household-rs/data/emoji-security-code-
//! wordlist.csv` (next to this crate). `src/emoji_code.rs` uses
//! `include_str!(env!("THEYOS_EMOJI_WORDLIST_PATH"))` to read it.
//!
//! Two sources, in priority order:
//!
//! 1. `THEYOS_EMOJI_WORDLIST` env var — set by Nix
//!    (`nix/packages/rust-workspace.nix`) when building inside the Nix
//!    sandbox, where path canonicalisation behaves differently from a
//!    plain `cargo build`.
//!
//! 2. Repo-relative fallback —
//!    `<CARGO_MANIFEST_DIR>/data/emoji-security-code-wordlist.csv` —
//!    works for plain `cargo build` / `cargo test` runs against the
//!    on-disk repo layout.
//!
//! The resolved absolute path is exported as `THEYOS_EMOJI_WORDLIST_PATH`
//! via `cargo:rustc-env`. We also emit `cargo:rerun-if-changed` so
//! editing the CSV triggers a rebuild.

use std::path::PathBuf;

fn main() {
    let env_path = std::env::var("THEYOS_EMOJI_WORDLIST")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from);

    let path = env_path.unwrap_or_else(|| {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest
            .join("data")
            .join("emoji-security-code-wordlist.csv")
    });

    let canon = path.canonicalize().unwrap_or_else(|_| path.clone());
    println!(
        "cargo:rustc-env=THEYOS_EMOJI_WORDLIST_PATH={}",
        canon.display()
    );
    println!("cargo:rerun-if-env-changed=THEYOS_EMOJI_WORDLIST");
    println!("cargo:rerun-if-changed={}", canon.display());
}
