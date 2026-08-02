//! Build-time channel resolution for the device static key (S1 g3 §3.3).
//!
//! The channel is a BUILD input (`THEYOS_CHANNEL` env → `theyos_channel`
//! cfg), never a runtime flag and never defaulted inside the crate: when no
//! arm supplies it, `compile_error!` in `lib.rs` stops the build. A missing
//! channel that silently picked one side would be a guard that fails open.

fn main() {
    println!("cargo:rustc-check-cfg=cfg(theyos_channel, values(\"dev\", \"release\"))");
    println!("cargo:rerun-if-env-changed=THEYOS_CHANNEL");
    // PROFILE comes from cargo itself, not from the debug_assertions proxy:
    // `[profile.release] debug-assertions = true` is a deliberate hardening
    // practice, and an operator who enables it must not reopen the channel
    // hole (reopening T1d). Derived from the profile, so there is no
    // pipeline list to maintain.
    let profile = std::env::var("PROFILE").unwrap_or_default();
    println!("cargo:rerun-if-env-changed=PROFILE");
    match std::env::var("THEYOS_CHANNEL") {
        Ok(channel) if channel == "dev" => {
            assert!(
                profile != "release",
                "release profile must not build the dev channel: set \
                 THEYOS_CHANNEL=release. A release binary carrying the dev \
                 device-static account is inexpressible, not watched (S1 g3 §3.2)."
            );
            println!("cargo:rustc-cfg=theyos_channel=\"dev\"");
        }
        Ok(channel) if channel == "release" => {
            println!("cargo:rustc-cfg=theyos_channel=\"release\"");
        }
        Ok(other) => panic!("THEYOS_CHANNEL must be 'dev' or 'release', got {other:?}"),
        Err(_) => {
            // Unset channel: allowed ONLY outside the release profile, where
            // lib.rs defaults it to dev under debug_assertions — the correct
            // value in the correct context. A release build with nothing
            // explicit is refused HERE, derived from cargo's PROFILE: the dev
            // channel must never ride into a release binary by omission.
            assert!(
                profile != "release",
                "release profile requires an explicit THEYOS_CHANNEL=release: \
                 the dev channel is only ever a debug-context default, never a \
                 release one (S1 g3 §3.2)."
            );
        }
    }
}
