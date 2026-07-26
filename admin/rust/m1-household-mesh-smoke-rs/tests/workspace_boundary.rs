use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn package_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_workspace() -> PathBuf {
    package_dir()
        .parent()
        .expect("package is a workspace child")
        .to_path_buf()
}

fn repository_root() -> PathBuf {
    rust_workspace()
        .parent()
        .and_then(Path::parent)
        .expect("admin/rust is below the repository root")
        .to_path_buf()
}

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path).expect("fixture source is UTF-8")
}

fn assert_only_versioned_signer_name(source: &str) {
    let prefix = ["THEYOS_HH_POP_SIGNER_ARGV_", "JSON"].concat();
    for (offset, _) in source.match_indices(&prefix) {
        let suffix = &source[offset + prefix.len()..];
        assert!(
            suffix.starts_with("_V1"),
            "unversioned signer environment name is forbidden"
        );
    }
}

fn rust_sources(root: &Path, output: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("source directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_sources(&path, output);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(path);
        }
    }
}

#[test]
fn package_is_a_binary_only_non_publishable_leaf() {
    let manifest = read(package_dir().join("Cargo.toml"));
    assert!(manifest.contains("publish = false"));
    assert!(manifest.contains("autobins = false"));
    assert!(manifest.contains("[[bin]]"));
    assert_eq!(manifest.matches("[[bin]]").count(), 1);
    assert!(manifest.contains("name = \"m1-household-mesh-smoke\""));
    assert!(!manifest.contains("[lib]"));
    assert!(!manifest.contains("[features]"));
    assert!(!package_dir().join("src/lib.rs").exists());
    assert!(!package_dir().join("src/bin").exists());

    let dependencies = manifest
        .split_once("[dependencies]")
        .and_then(|(_, suffix)| suffix.split_once("[lints]"))
        .map(|(dependencies, _)| dependencies)
        .expect("closed dependency section");
    let actual_dependencies: BTreeSet<&str> = dependencies
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name.trim()))
        .filter(|name| !name.is_empty())
        .collect();
    let approved_dependencies = BTreeSet::from([
        "base64",
        "clap",
        "libc",
        "rand",
        "serde",
        "serde_json",
        "ureq",
        "url",
    ]);
    assert_eq!(
        actual_dependencies, approved_dependencies,
        "leaf dependency keys must stay at the reviewed external set"
    );
    let actual_declarations: BTreeSet<&str> = dependencies
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let approved_declarations = BTreeSet::from([
        "base64 = { workspace = true }",
        "clap = \"4\"",
        "libc = { workspace = true }",
        "rand = \"0.8\"",
        "serde = { workspace = true }",
        "serde_json = { workspace = true }",
        "ureq = { version = \"2\", default-features = false }",
        "url = \"2\"",
    ]);
    assert_eq!(
        actual_declarations, approved_declarations,
        "leaf dependency declarations must stay byte-explicit and external"
    );
    assert_eq!(
        manifest.matches("dependencies]").count(),
        1,
        "no target, build, or development dependency section is permitted"
    );

    let workspace_manifest = read(rust_workspace().join("Cargo.toml"));
    assert!(workspace_manifest.contains("\"m1-household-mesh-smoke-rs\","));

    let mut references = Vec::new();
    for entry in fs::read_dir(rust_workspace()).expect("workspace directory") {
        let path = entry.expect("workspace entry").path();
        let manifest_path = path.join("Cargo.toml");
        if manifest_path.is_file() && read(&manifest_path).contains("m1-household-mesh-smoke-rs") {
            references.push(manifest_path);
        }
    }
    assert_eq!(
        references,
        [package_dir().join("Cargo.toml")],
        "no normal crate may depend on the smoke binary package"
    );
}

#[test]
fn crate_and_runbook_remain_neutral_and_non_operational() {
    let mut sources = Vec::new();
    rust_sources(&package_dir(), &mut sources);
    let runbook = repository_root().join("docs/m1-household-mesh-smoke-runbook.md");
    sources.push(runbook);

    let forbidden = [
        ["Product ", "A"].concat(),
        ["product", "_a"].concat(),
        ["product", "-a"].concat(),
        ["n", "vpn"].concat(),
        ["10.", "44."].concat(),
        ["Claw", "ShareBridge"].concat(),
        ["Ip", "Tunnel"].concat(),
        ["ip", "_tunnel"].concat(),
        ["rout", "ing"].concat(),
    ];
    for path in sources {
        let source = read(&path);
        for marker in &forbidden {
            assert!(
                !source.contains(marker),
                "neutral smoke surface contains a forbidden marker"
            );
        }
        for token in source.split(|character: char| !character.is_ascii_alphanumeric()) {
            assert_ne!(
                token,
                ["T", "UN"].concat(),
                "neutral smoke surface contains a forbidden symbol"
            );
        }
    }
}

#[test]
fn signer_contract_is_local_versioned_and_shell_free() {
    let mut sources = Vec::new();
    rust_sources(&package_dir().join("src"), &mut sources);
    let source = sources.iter().map(read).collect::<Vec<_>>().join("\n");
    let adapters = read(package_dir().join("src/adapters.rs"));
    let production_adapters = adapters
        .split_once("#[cfg(test)]")
        .map_or(adapters.as_str(), |(production, _)| production);
    let runbook = read(repository_root().join("docs/m1-household-mesh-smoke-runbook.md"));

    assert!(source.contains("THEYOS_HH_POP_SIGNER_ARGV_JSON_V1"));
    assert_only_versioned_signer_name(&source);
    assert_only_versioned_signer_name(&runbook);
    assert!(source.contains("THEYOS_HH_POP_SIGNER_CMD"));
    assert!(!source.contains("shlex"));
    assert!(!source.contains("Command::new(\"bash\")"));
    assert!(!source.contains("Command::new(\"sh\")"));
    assert!(!source.contains("/bin/bash"));
    assert!(!source.contains("/bin/sh"));
    for persistent_capture in [
        "NamedTempFile",
        "tempfile",
        "File::create",
        "OpenOptions",
        "fs::write",
    ] {
        assert!(
            !production_adapters.contains(persistent_capture),
            "signer output must never enter a named or persistent path"
        );
    }
    assert!(source.contains(".env_clear()"));
    assert!(source.contains(".stdin(Stdio::null())"));
    assert!(production_adapters.contains(".process_group(0)"));
    assert!(production_adapters.contains("SIGKILL"));

    let e2e_manifest = read(rust_workspace().join("e2e-rs/Cargo.toml"));
    assert!(!e2e_manifest.contains("m1-household-mesh-smoke"));
    assert!(!e2e_manifest.contains("THEYOS_HH_POP_SIGNER_ARGV_JSON_V1"));
}

#[test]
fn operational_source_has_no_mutation_or_remote_execution_surface() {
    let mut sources = Vec::new();
    rust_sources(&package_dir().join("src"), &mut sources);
    let source = sources.iter().map(read).collect::<Vec<_>>().join("\n");

    let forbidden = [
        ["Command::new(\"", "ssh", "\")"].concat(),
        ["Command::new(\"", "scp", "\")"].concat(),
        ["Command::new(\"", "rsync", "\")"].concat(),
        ["Command::new(\"", "open", "\")"].concat(),
        ["Command::new(\"", "launchctl", "\")"].concat(),
        ["Command::new(\"", "pkill", "\")"].concat(),
        ["pair-machine/local/", "stage"].concat(),
        ["pair-machine/local/", "finalize"].concat(),
        ["bootstrap/", "initialize"].concat(),
        ["bootstrap/", "teardown"].concat(),
    ];
    for marker in forbidden {
        assert!(
            !source.contains(&marker),
            "operational binary contains a forbidden effect surface"
        );
    }

    for required in [
        "/Applications/Soyeht Dev.app/Contents/Info.plist",
        "com.soyeht.mac.dev",
        "SoyehtDev",
        "http://127.0.0.1:8101/bootstrap/status",
        "http://127.0.0.1:8091/bootstrap/status",
        "/api/v1/household/machines",
        "/api/v1/household/reachability/echo",
        ".try_proxy_from_env(false)",
        ".redirects(0)",
    ] {
        assert!(
            source.contains(required),
            "a fixed Dev-only or bounded HTTP invariant is missing"
        );
    }
}

#[test]
fn operational_shell_scripts_are_absent() {
    let scripts = repository_root().join("scripts");
    for removed in [
        "run-m1-household-mesh-smoke.sh",
        "test_run_m1_household_mesh_smoke.sh",
    ] {
        assert!(!scripts.join(removed).exists());
    }
}
