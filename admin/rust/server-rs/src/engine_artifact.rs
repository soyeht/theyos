//! Identity of the executable loaded into this process, not of the file that
//! currently occupies its install path. A staged replacement must not make an
//! old process report the new artifact. The Mach-O UUID identifies a linked
//! image; it is not a signature, authorization token, or integrity check.

use serde::Serialize;

/// Identifies this process incarnation independently of PID reuse. Used only
/// by runtime readback, never by the standalone artifact identity command.
#[must_use]
pub fn process_boot_id() -> &'static str {
    static BOOT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    BOOT.get_or_init(|| format!("{:032x}", rand::random::<u128>()))
}

#[derive(Debug, Serialize)]
pub struct EngineArtifact {
    pub version: &'static str,
    pub git_sha: &'static str,
    pub image_uuid: Option<String>,
    pub pty_supervisor_protocol: u16,
}

#[must_use]
pub fn current() -> EngineArtifact {
    EngineArtifact {
        version: env!("CARGO_PKG_VERSION"),
        git_sha: env!("THEYOS_SERVER_BUILD_GIT_SHA"),
        image_uuid: image_uuid(),
        pty_supervisor_protocol: terminal_rs::supervisor_wire::VERSION,
    }
}

#[cfg(not(target_os = "macos"))]
fn image_uuid() -> Option<String> {
    // No path-based fallback: after replacement it would describe another
    // executable. Consumers must treat unsupported identity as unknown.
    None
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)] // Read-only dyld API; the loaded executable owns these bytes.
fn image_uuid() -> Option<String> {
    unsafe extern "C" {
        fn _dyld_get_image_header(image_index: u32) -> *const u8;
    }
    // SAFETY: dyld owns the main executable's header and load commands for
    // this process's lifetime. Index zero names that executable. Supported
    // macOS targets are 64-bit; reject another header before reading commands.
    unsafe {
        let header = _dyld_get_image_header(0);
        if header.is_null() {
            return None;
        }
        let bytes = std::slice::from_raw_parts(header, 32);
        if u32::from_ne_bytes(bytes[0..4].try_into().ok()?) != 0xfeed_facf {
            return None;
        }
        let count = u32::from_ne_bytes(bytes[16..20].try_into().ok()?);
        let size = u32::from_ne_bytes(bytes[20..24].try_into().ok()?) as usize;
        if size > 1024 * 1024 {
            return None;
        }
        uuid_from_commands(std::slice::from_raw_parts(header.add(32), size), count)
    }
}

#[cfg(any(target_os = "macos", test))]
fn uuid_from_commands(mut bytes: &[u8], count: u32) -> Option<String> {
    let mut found = None;
    for _ in 0..count {
        let command = u32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?);
        let size = u32::from_ne_bytes(bytes.get(4..8)?.try_into().ok()?) as usize;
        if size < 8 || size % 8 != 0 {
            return None;
        }
        let record = bytes.get(..size)?;
        if command == 0x1b {
            // LC_UUID has one 16-byte UUID and no variable-length payload.
            if size != 24 || found.is_some() {
                return None;
            }
            let hex = b"0123456789abcdef";
            let mut uuid = String::with_capacity(32);
            for byte in &record[8..] {
                uuid.push(char::from(hex[usize::from(byte >> 4)]));
                uuid.push(char::from(hex[usize::from(byte & 15)]));
            }
            found = Some(uuid);
        }
        bytes = &bytes[size..];
    }
    if !bytes.is_empty() {
        return None;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_or_ambiguous_commands_cannot_claim_identity() {
        let mut record = Vec::new();
        record.extend(0x1b_u32.to_ne_bytes());
        record.extend(24_u32.to_ne_bytes());
        record.extend(0_u8..16);
        assert_eq!(
            uuid_from_commands(&record, 1).as_deref(),
            Some("000102030405060708090a0b0c0d0e0f")
        );
        for end in 0..record.len() {
            assert!(uuid_from_commands(&record[..end], 1).is_none());
        }
        assert!(uuid_from_commands(&record, 2).is_none());
        assert!(uuid_from_commands(&[record.clone(), record.clone()].concat(), 2).is_none());
        record[4..8].copy_from_slice(&0_u32.to_ne_bytes());
        assert!(uuid_from_commands(&record, 1).is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn loaded_image_matches_linker_uuid_reported_by_system_tool() {
        let output = std::process::Command::new("/usr/bin/dwarfdump")
            .arg("--uuid")
            .arg(std::env::current_exe().unwrap())
            .output()
            .unwrap();
        assert!(output.status.success());
        let report = String::from_utf8(output.stdout)
            .unwrap()
            .replace('-', "")
            .to_lowercase();
        let loaded = image_uuid().expect("linked macOS executable has LC_UUID");
        assert!(
            report.contains(&loaded),
            "loaded image must match the linker UUID"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn image_identity_child() {
        let Some(root) = std::env::var_os("SOYEHT_IMAGE_IDENTITY_FIXTURE") else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        std::fs::write(root.join("boot-before"), process_boot_id()).unwrap();
        std::fs::write(root.join("before"), image_uuid().unwrap()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !root.join("replaced").exists() {
            assert!(std::time::Instant::now() < deadline, "replacement deadline");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::fs::write(root.join("after"), image_uuid().unwrap()).unwrap();
        std::fs::write(root.join("boot-after"), process_boot_id()).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn replacing_install_path_does_not_change_running_image_identity() {
        use std::{
            fs,
            process::Command,
            time::{Duration, Instant},
        };
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("engine-fixture");
        // A new link changes no bytes of the original test executable.
        fs::hard_link(std::env::current_exe().unwrap(), &executable).unwrap();
        let mut child = ChildGuard(
            Command::new(&executable)
                .args(["--exact", "engine_artifact::tests::image_identity_child"])
                .env("SOYEHT_IMAGE_IDENTITY_FIXTURE", root.path())
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !root.path().join("before").exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "child exited before readiness"
            );
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let before = fs::read_to_string(root.path().join("before")).unwrap();
        let replacement = root.path().join("replacement");
        fs::copy("/usr/bin/true", &replacement).unwrap();
        fs::rename(&replacement, &executable).unwrap();
        let output = Command::new("/usr/bin/dwarfdump")
            .arg("--uuid")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(output.status.success());
        let installed = String::from_utf8(output.stdout)
            .unwrap()
            .replace('-', "")
            .to_lowercase();
        assert!(
            !installed.contains(&before),
            "control must actually replace the image"
        );
        fs::write(root.path().join("replaced"), b"go").unwrap();
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            before,
            fs::read_to_string(root.path().join("after")).unwrap()
        );
        let child_boot = fs::read_to_string(root.path().join("boot-before")).unwrap();
        assert_eq!(child_boot.len(), 32);
        assert_ne!(
            child_boot,
            process_boot_id(),
            "same image, different process incarnation"
        );
        assert_eq!(
            child_boot,
            fs::read_to_string(root.path().join("boot-after")).unwrap()
        );
    }
}
