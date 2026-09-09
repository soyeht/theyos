//! `theyos-engine accessibility [--prompt]` — is THIS executable trusted for
//! macOS Accessibility, and optionally ask for it.
//!
//! WHY THE ENGINE ANSWERS THIS. macOS grants Accessibility to the process
//! responsible for a request, identified by its executable. The PTY
//! supervisor runs from the engine file (`theyos-engine ptyd`) and is the
//! parent of every pane shell, so the grant that matters to an agent in a
//! pane is the one on `theyos-engine` — not the one on the app. The Mac app
//! used to check and request for itself, which told the person "granted"
//! while every pane was refused (2026-09-08). Now the app runs this
//! subcommand with launch responsibility disclaimed, so both the answer and
//! the system prompt carry the engine's identity, and one grant covers the
//! supervisor and every shell it owns.
//!
//! Output is one JSON object on stdout: `{"trusted": bool, "prompted": bool}`.
//! On platforms without TCC it reports `trusted: true, supported: false`.

/// Runs the subcommand. `args` excludes the program name and the word
/// `accessibility`. Returns the process exit code.
#[must_use]
pub fn run(args: &[String]) -> i32 {
    let prompt = match args {
        [] => false,
        [flag] if flag == "--prompt" => true,
        _ => {
            eprintln!("usage: theyos-engine accessibility [--prompt]");
            return 2;
        }
    };
    let report = platform::report(prompt);
    println!("{report}");
    0
}

#[cfg(target_os = "macos")]
mod platform {
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::string::{CFString, CFStringRef};

    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        static kAXTrustedCheckOptionPrompt: CFStringRef;
        fn AXIsProcessTrustedWithOptions(options: CFDictionaryRef) -> bool;
        fn AXIsProcessTrusted() -> bool;
    }

    pub fn report(prompt: bool) -> String {
        let trusted = if prompt {
            // SAFETY: `kAXTrustedCheckOptionPrompt` is a process-lifetime
            // constant owned by the framework; the dictionary outlives the
            // call.
            unsafe {
                let key = CFString::wrap_under_get_rule(kAXTrustedCheckOptionPrompt);
                let options = CFDictionary::from_CFType_pairs(&[(key, CFBoolean::true_value())]);
                AXIsProcessTrustedWithOptions(options.as_concrete_TypeRef())
            }
        } else {
            // SAFETY: no arguments, no shared state.
            unsafe { AXIsProcessTrusted() }
        };
        serde_json::json!({"trusted": trusted, "prompted": prompt, "supported": true}).to_string()
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    pub fn report(prompt: bool) -> String {
        serde_json::json!({"trusted": true, "prompted": prompt, "supported": false}).to_string()
    }
}
