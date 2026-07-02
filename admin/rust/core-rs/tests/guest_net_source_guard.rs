use std::fs;
use std::path::{Path, PathBuf};

const OWNER: &str = "core-rs/src/guest_net.rs";

const OWNED_LITERALS: &[&str] = &[
    "vmlinux-6.1.155",
    "eth0",
    "tap1",
    "tap0",
    "172.16.0.1",
    "172.16.0.1/30",
    "172.16.0.2",
    "06:00:ac:10:00:02",
    "AA:FC:00:00:00:01",
    "10.0.2.100",
    "18790",
    "19999",
    "22000",
    "23999",
    "24000",
    "25999",
];

#[test]
fn guest_net_literals_have_one_production_owner() {
    let rust_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("core-rs has a workspace parent");

    let mut files = Vec::new();
    collect_rust_files(rust_root, &mut files);
    files.sort();

    let mut hits = Vec::new();
    for path in files {
        let rel = path.strip_prefix(rust_root).expect("path under rust root");
        let rel = normalize_path(rel);

        if rel == OWNER || rel.contains("/tests/") || rel.contains("/benches/") {
            continue;
        }

        let content = fs::read_to_string(&path).expect("read source file");
        for (line_number, line) in production_lines(&content) {
            for literal in OWNED_LITERALS {
                if line.contains(literal) {
                    hits.push(format!("{rel}:{line_number}: {literal}"));
                }
            }
        }
    }

    assert!(
        hits.is_empty(),
        "guest-net literals must live in {OWNER}; production duplicates:\n{}",
        hits.join("\n")
    );
}

#[test]
fn guest_net_declares_one_firecracker_guest_mac_constant() {
    let owner_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("core-rs has a workspace parent")
        .join(OWNER);
    let content = fs::read_to_string(owner_path).expect("read guest-net owner");

    let guest_mac_consts = content
        .lines()
        .filter(|line| line.trim_start().starts_with("pub const FIRECRACKER_"))
        .filter(|line| line.contains("GUEST_MAC"))
        .collect::<Vec<_>>();

    assert_eq!(
        guest_mac_consts,
        vec![r#"pub const FIRECRACKER_GUEST_MAC: &str = "06:00:ac:10:00:02";"#],
        "guest_net must expose exactly one production Firecracker guest MAC constant"
    );
    assert!(!content.contains("FIRECRACKER_RUNTIME_GUEST_MAC"));
    assert!(!content.contains("FIRECRACKER_IMAGEBUILD_GUEST_MAC"));
}

#[test]
fn firecracker_kernel_package_keeps_tun_prerequisite_load_bearing() {
    let rust_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("core-rs has a workspace parent");
    let repo_root = rust_root
        .parent()
        .and_then(Path::parent)
        .expect("rust workspace has a repo parent");
    let kernel_nix = fs::read_to_string(repo_root.join("nix/packages/kernel.nix"))
        .expect("read firecracker kernel package");
    let module_nix =
        fs::read_to_string(repo_root.join("nix/module.nix")).expect("read theyOS NixOS module");
    let kernel_config =
        fs::read_to_string(repo_root.join("nix/packages/firecracker-kernel-x86_64.config"))
            .expect("read firecracker kernel config");

    assert!(
        kernel_nix.contains("kernelVersion = \"6.1.155\";"),
        "kernel package must stay pinned to the Firecracker guest kernel version theyOS expects"
    );
    assert!(
        kernel_nix.contains("linux-${kernelVersion}.tar.xz"),
        "per-Claw VPN Linux guests need a source-built kernel, not the old prebuilt kernel"
    );
    assert!(
        kernel_nix
            .contains("https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${kernelVersion}.tar.xz"),
        "kernel package must fetch the pinned mainline kernel source from kernel.org"
    );
    assert!(
        kernel_config.contains("Linux/x86 6.1.155 Kernel Configuration"),
        "kernel config must stay aligned with the mainline 6.1.155 Firecracker CI config"
    );
    assert!(
        kernel_config.contains("\nCONFIG_TUN=y\n"),
        "checked-in kernel config must keep CONFIG_TUN built in"
    );
    assert!(
        kernel_config.contains("\nCONFIG_TUN_VNET_CROSS_LE=y\n"),
        "checked-in kernel config must keep CONFIG_TUN_VNET_CROSS_LE built in"
    );
    assert!(
        kernel_config.contains("\n# CONFIG_KEXEC is not set\n")
            && kernel_config.contains("\n# CONFIG_KEXEC_FILE is not set\n")
            && kernel_config.contains("\n# CONFIG_KEXEC_CORE is not set\n")
            && kernel_config.contains("\n# CONFIG_ARCH_HAS_KEXEC_PURGATORY is not set\n"),
        "checked-in kernel config must keep unused kexec/purgatory disabled for the Nix source build"
    );
    assert!(
        kernel_nix.contains("for opt in TUN TUN_VNET_CROSS_LE"),
        "kernel package must force-enable both TUN options"
    );
    assert!(
        kernel_nix.contains("grep -q '^CONFIG_TUN=y'"),
        "kernel package must fail closed if CONFIG_TUN is not built in"
    );
    assert!(
        kernel_nix.contains("grep -q '^CONFIG_TUN_VNET_CROSS_LE=y'"),
        "kernel package must fail closed if CONFIG_TUN_VNET_CROSS_LE is not built in"
    );
    assert!(
        kernel_nix.contains("for opt in KEXEC KEXEC_FILE KEXEC_CORE ARCH_HAS_KEXEC_PURGATORY")
            && kernel_nix.contains("grep -q \"^CONFIG_$opt=y\""),
        "kernel package must fail closed if olddefconfig enables unused kexec/purgatory"
    );
    assert!(
        kernel_nix.contains("cp vmlinux \"$out\""),
        "kernel package must remain a vmlinux file because nix/module.nix symlinks kernelPackage directly"
    );
    assert!(
        module_nix.contains(
            "ln -sf ${cfg.kernelPackage} /home/${cfg.user}/firecracker/assets/vmlinux-6.1.155"
        ),
        "nix/module.nix must keep symlinking kernelPackage directly, which is why the kernel package output is a file"
    );
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).expect("read source directory");
    for entry in entries {
        let entry = entry.expect("read directory entry");
        let path = entry.path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name == "target" || name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn normalize_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn production_lines(content: &str) -> Vec<(usize, &str)> {
    let mut lines = Vec::new();
    let mut skip_cfg_test_item = false;
    let mut skip_depth: Option<i32> = None;

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();
        if let Some(depth) = skip_depth {
            let depth = depth + brace_delta(line);
            if depth > 0 {
                skip_depth = Some(depth);
            } else {
                skip_depth = None;
            }
            continue;
        }

        if trimmed.starts_with("#[cfg(test)]") {
            skip_cfg_test_item = true;
            continue;
        }

        if skip_cfg_test_item {
            if trimmed.is_empty() || trimmed.starts_with("#[") {
                continue;
            }
            let depth = brace_delta(line);
            if depth > 0 {
                skip_depth = Some(depth);
            }
            skip_cfg_test_item = false;
            continue;
        }

        if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }
        lines.push((idx + 1, line));
    }

    lines
}

fn brace_delta(line: &str) -> i32 {
    line.chars().fold(0, |depth, ch| match ch {
        '{' => depth + 1,
        '}' => depth - 1,
        _ => depth,
    })
}

#[test]
fn production_line_filter_resumes_after_cfg_test_item() {
    let content = r#"
pub const BEFORE: &str = "before";
#[cfg(test)]
mod tests {
    const TEST_ONLY: &str = "tap0";
}
pub const AFTER: &str = "tap1";
"#;

    let lines = production_lines(content)
        .into_iter()
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n");

    assert!(lines.contains("BEFORE"));
    assert!(!lines.contains("TEST_ONLY"));
    assert!(lines.contains("AFTER"));
}
