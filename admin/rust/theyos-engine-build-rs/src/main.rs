use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const UNSAFE_BUILD_ENV: [&str; 26] = [
    "AR",
    "BINDGEN_EXTRA_CLANG_ARGS",
    "CC",
    "CFLAGS",
    "CPP",
    "CPPFLAGS",
    "CXX",
    "CXXFLAGS",
    "DEVELOPER_DIR",
    "DOCKER_OPTS",
    "LD",
    "LDFLAGS",
    "MACOSX_DEPLOYMENT_TARGET",
    "PKG_CONFIG_PATH",
    "RANLIB",
    "RUSTFLAGS",
    "RUSTDOCFLAGS",
    "SDKROOT",
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTC",
    "RUSTDOC",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_TARGET",
];

const UNSAFE_BUILD_ENV_PREFIX: [&str; 11] = [
    "AR_",
    "CARGO_BUILD_",
    "CARGO_PROFILE_",
    "CARGO_TARGET_",
    "CC_",
    "CFLAGS_",
    "CROSS_",
    "CXX_",
    "CXXFLAGS_",
    "LDFLAGS_",
    "PKG_CONFIG_",
];

const UNSAFE_BUILD_ENV_SUFFIX: [&str; 8] = [
    "_AR",
    "_CC",
    "_CFLAGS",
    "_CXX",
    "_CXXFLAGS",
    "_LD",
    "_LDFLAGS",
    "_RANLIB",
];

const TRACKED_PKG_CONFIG_PATH: &str = "";

const REPO_INPUT_OVERRIDE_ENV: [&str; 3] = [
    "CLAWS_MANIFEST_YML",
    "CLAWS_CATALOG_JSON",
    "THEYOS_EMOJI_WORDLIST",
];

const CANONICAL_CHILD_ENV: [&str; 10] = [
    "HOME",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "TMPDIR",
    "PATH",
    "LC_ALL",
    "LANG",
    "RUSTUP_TOOLCHAIN",
    "CARGO_TARGET_DIR",
    "CARGO_NET_OFFLINE",
];

const X86_64_MUSL_IMAGE: &str = "ghcr.io/cross-rs/x86_64-unknown-linux-musl:0.2.5@sha256:77db671d8356a64ae72a3e1415e63f547f26d374fbe3c4762c1cd36c7eac7b99";
const AARCH64_MUSL_IMAGE: &str = "ghcr.io/cross-rs/aarch64-unknown-linux-musl:0.2.5@sha256:702154f52b2d8091671aa2c84d5582d849f949977228c735ff8462f93cc0e1e4";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args_os();
    let _program = args.next();
    let command = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(usage)?;

    match command.as_str() {
        "build" => {
            let target = args
                .next()
                .and_then(|value| value.into_string().ok())
                .ok_or_else(usage)?;
            let build_tool = args
                .next()
                .and_then(|value| value.into_string().ok())
                .unwrap_or_else(|| "cargo".to_owned());
            if args.next().is_some() {
                return Err(usage());
            }
            build_engine(&target, &build_tool)
        }
        "stage" => {
            let source_dir = args.next().map(PathBuf::from).ok_or_else(usage)?;
            let destination = args.next().map(PathBuf::from).ok_or_else(usage)?;
            if args.next().is_some() {
                return Err(usage());
            }
            stage_engine(&source_dir, &destination)
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: theyos-engine-build build TARGET [cargo|cross]\n       theyos-engine-build stage SOURCE_RELEASE_DIR DESTINATION".to_owned()
}

fn workspace_paths() -> Result<(PathBuf, PathBuf), String> {
    let rust_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("build tool manifest has no workspace parent")?
        .to_path_buf();
    let repo_root = rust_root
        .parent()
        .and_then(Path::parent)
        .ok_or("Rust workspace has no repository parent")?
        .to_path_buf();
    Ok((repo_root, rust_root))
}

fn build_engine(target: &str, build_tool: &str) -> Result<(), String> {
    if target.is_empty()
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(format!("invalid Rust target triple: {target}"));
    }
    if !matches!(build_tool, "cargo" | "cross") {
        return Err(format!(
            "unsupported theyos-engine build tool: {build_tool}"
        ));
    }
    for (name, value) in env::vars_os() {
        let name = name.to_string_lossy();
        if is_unsafe_build_env(&name) && !value.is_empty() {
            return Err(format!(
                "{name} must be unset for the canonical theyos-engine build"
            ));
        }
    }

    let (repo_root, rust_root) = workspace_paths()?;
    reject_ancestor_cargo_configs(&repo_root)?;
    reject_cargo_home_config()?;
    validate_tracked_pkg_config_path()?;
    let canonical_env = canonical_child_environment()?;
    let expected_rust = expected_rust_version(&rust_root.join("rust-toolchain.toml"))?;
    let mut rustc = Command::new("rustc");
    apply_canonical_environment(&mut rustc, &canonical_env);
    let rustc_verbose = command_stdout(rustc.current_dir(&rust_root).arg("-vV"))?;
    let actual_rust = rustc_verbose
        .lines()
        .find_map(|line| line.strip_prefix("release: "))
        .ok_or("rustc -vV did not report a release")?;
    let host = rustc_verbose
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or("rustc -vV did not report a host")?;
    if actual_rust != expected_rust {
        return Err(format!(
            "production theyos-engine requires rustc {expected_rust}, found {actual_rust}"
        ));
    }
    validate_rustup_toolchain(&expected_rust, host)?;

    let source_sha = env::var("THEYOS_BUILD_GIT_SHA")
        .map_err(|_| "THEYOS_BUILD_GIT_SHA must be supplied by the canonical caller")?;
    if source_sha.len() != 40
        || !source_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("THEYOS_BUILD_GIT_SHA must be a full lowercase Git SHA".to_owned());
    }

    let mut build_args = vec![
        "build",
        "--quiet",
        "--manifest-path",
        "Cargo.toml",
        "--locked",
        "--release",
        "--target",
        target,
        "--no-default-features",
        "--package",
        "server-rs",
        "--package",
        "llm-proxy-rs",
        "--package",
        "soyeht-rs",
        "--package",
        "store-rs",
        "--package",
        "terminal-rs",
    ];
    if target.ends_with("-apple-darwin") {
        build_args.extend(["--package", "vmrunner-macos-rs"]);
    } else {
        build_args.extend(["--package", "vmrunner-rs", "--package", "imagebuilder-rs"]);
    }
    let mut build = Command::new(build_tool);
    apply_canonical_environment(&mut build, &canonical_env);
    let target_root = target_root_for(&rust_root)?;
    fs::create_dir_all(target_root.join("phase0-generated"))
        .map_err(|error| format!("failed to create Phase 0 generated output directory: {error}"))?;
    build
        .current_dir(&rust_root)
        .args(&build_args)
        .env("THEYOS_BUILD_GIT_SHA", &source_sha)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS", "false");
    for name in REPO_INPUT_OVERRIDE_ENV {
        build.env_remove(name);
    }
    build
        .env("CLAWS_MANIFEST_YML", repo_root.join("claws/manifest.yml"))
        .env(
            "CLAWS_CATALOG_JSON",
            target_root.join("phase0-generated/claws-catalog.json"),
        )
        .env(
            "THEYOS_EMOJI_WORDLIST",
            rust_root.join("household-rs/data/emoji-security-code-wordlist.csv"),
        );
    let status = if build_tool == "cross" {
        run_container_build(
            target,
            &repo_root,
            &target_root_for(&rust_root)?,
            &canonical_env,
            &source_sha,
            &build_args,
        )?
    } else {
        build
            .status()
            .map_err(|error| format!("failed to launch {build_tool}: {error}"))?
    };
    if !status.success() {
        return Err(format!(
            "canonical theyos-engine build failed for {target} with {build_tool}"
        ));
    }

    let release_dir = target_root.join(target).join("release");
    let binary = release_dir.join("server");
    let depfile = release_dir.join("server.d");
    let proxy_binary = release_dir.join("theyos-llm-proxy");
    let proxy_depfile = release_dir.join("theyos-llm-proxy.d");
    require_executable_regular_file(&binary)?;
    if !depfile.is_file() {
        return Err(format!(
            "canonical theyos-engine build did not produce depfile: {}",
            depfile.display()
        ));
    }
    require_executable_regular_file(&proxy_binary)?;
    if !proxy_depfile.is_file() {
        return Err(format!(
            "canonical theyos-engine build did not produce proxy depfile: {}",
            proxy_depfile.display()
        ));
    }
    let published_helpers: &[&str] = if target.ends_with("-apple-darwin") {
        &[
            "vmrunner_macos_ipc",
            "store-ipc",
            "terminal-ipc",
            "theyos-ssh",
            "theyos-provision-inject",
        ]
    } else {
        &[
            "soyeht",
            "vmrunner_ipc",
            "fc-ssh",
            "store-ipc",
            "terminal-ipc",
            "imagebuilder",
        ]
    };
    for helper in published_helpers {
        let helper_binary = release_dir.join(helper);
        require_executable_regular_file(&helper_binary)?;
        if !release_dir.join(format!("{helper}.d")).is_file() {
            return Err(format!(
                "canonical theyos-engine build did not produce helper depfile: {}",
                release_dir.join(format!("{helper}.d")).display()
            ));
        }
    }
    println!("{}", binary.display());
    Ok(())
}

fn target_root_for(rust_root: &Path) -> Result<PathBuf, String> {
    Ok(env::var_os("CARGO_TARGET_DIR").map_or_else(
        || rust_root.join("target"),
        |value| {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                path
            } else {
                rust_root.join(path)
            }
        },
    ))
}

fn is_unsafe_build_env(name: &str) -> bool {
    if matches!(name, "CARGO_TARGET_DIR" | "PKG_CONFIG_PATH") {
        return false;
    }
    UNSAFE_BUILD_ENV.contains(&name)
        || UNSAFE_BUILD_ENV_PREFIX
            .iter()
            .any(|prefix| name.starts_with(prefix))
        || UNSAFE_BUILD_ENV_SUFFIX
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

fn canonical_child_environment() -> Result<Vec<(OsString, OsString)>, String> {
    if env::var("THEYOS_PHASE0_CLEAN_ENV").as_deref() != Ok("1") {
        return Err("canonical theyos-engine build requires an env-cleared caller".to_owned());
    }

    let mut values = Vec::with_capacity(CANONICAL_CHILD_ENV.len());
    for name in CANONICAL_CHILD_ENV {
        let value = env::var_os(name)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("canonical build environment is missing {name}"))?;
        values.push((OsString::from(name), value));
    }

    for name in [
        "HOME",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "TMPDIR",
        "CARGO_TARGET_DIR",
    ] {
        let value = values
            .iter()
            .find_map(|(candidate, value)| (candidate == name).then_some(value))
            .ok_or_else(|| format!("canonical build environment is missing {name}"))?;
        if !Path::new(value).is_absolute() {
            return Err(format!(
                "canonical build environment requires absolute {name}"
            ));
        }
    }

    let path = values
        .iter()
        .find_map(|(candidate, value)| (candidate == "PATH").then_some(value))
        .and_then(|value| value.to_str())
        .ok_or("canonical PATH must be valid Unicode")?;
    if path
        .split(':')
        .any(|entry| entry.is_empty() || !Path::new(entry).is_absolute())
    {
        return Err("canonical PATH must contain only absolute, non-empty entries".to_owned());
    }

    for name in ["LC_ALL", "LANG"] {
        let value = values
            .iter()
            .find_map(|(candidate, value)| (candidate == name).then_some(value))
            .and_then(|value| value.to_str());
        if value != Some("C") {
            return Err(format!("canonical build environment requires {name}=C"));
        }
    }
    let offline = values
        .iter()
        .find_map(|(candidate, value)| (candidate == "CARGO_NET_OFFLINE").then_some(value))
        .and_then(|value| value.to_str());
    if offline != Some("true") {
        return Err("canonical build environment requires Cargo offline mode".to_owned());
    }

    Ok(values)
}

fn apply_canonical_environment(command: &mut Command, values: &[(OsString, OsString)]) {
    command.env_clear();
    command.envs(values.iter().map(|(name, value)| (name, value)));
}

fn validate_tracked_pkg_config_path() -> Result<(), String> {
    if let Some(value) = env::var_os("PKG_CONFIG_PATH")
        && value != TRACKED_PKG_CONFIG_PATH
    {
        return Err(
            "PKG_CONFIG_PATH differs from the frozen admin/rust/.cargo/config.toml".to_owned(),
        );
    }
    Ok(())
}

fn validate_rustup_toolchain(expected_rust: &str, host: &str) -> Result<(), String> {
    let Some(value) = env::var_os("RUSTUP_TOOLCHAIN") else {
        return Ok(());
    };
    let value = value
        .to_str()
        .ok_or("RUSTUP_TOOLCHAIN must be valid Unicode")?;
    let expected_host_toolchain = format!("{expected_rust}-{host}");
    if value != expected_rust && value != expected_host_toolchain {
        return Err(format!(
            "RUSTUP_TOOLCHAIN must select the pinned {expected_rust} toolchain for {host}"
        ));
    }
    Ok(())
}

fn phase0_image(target: &str) -> Result<&'static str, String> {
    match target {
        "x86_64-unknown-linux-musl" => Ok(X86_64_MUSL_IMAGE),
        "aarch64-unknown-linux-musl" => Ok(AARCH64_MUSL_IMAGE),
        _ => Err(format!("no pinned Phase 0 OCI image exists for {target}")),
    }
}

fn run_container_build(
    target: &str,
    repo_root: &Path,
    target_root: &Path,
    canonical_env: &[(OsString, OsString)],
    source_sha: &str,
    build_args: &[&str],
) -> Result<std::process::ExitStatus, String> {
    let docker = executable_from_path("docker")?;
    let image = phase0_image(target)?;
    let cargo_home = canonical_value(canonical_env, "CARGO_HOME")?;
    let rustup_home = canonical_value(canonical_env, "RUSTUP_HOME")?;
    let rust_version = canonical_value(canonical_env, "RUSTUP_TOOLCHAIN")?;
    let platform = if target.starts_with("aarch64-") {
        Some("linux/arm64")
    } else {
        None
    };

    let mut command = Command::new(docker);
    command.args([
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
    ]);
    if let Some(platform) = platform {
        command.args(["--platform", platform]);
    }
    command
        .args([
            "--mount",
            &format!(
                "type=bind,src={},dst=/project,readonly",
                repo_root.display()
            ),
            "--mount",
            &format!("type=bind,src={},dst=/target", target_root.display()),
            "--mount",
            &format!("type=bind,src={},dst=/phase0-cargo,readonly", cargo_home),
            "--mount",
            &format!("type=bind,src={},dst=/phase0-rustup,readonly", rustup_home),
            "--mount",
            &format!(
                "type=bind,src={},dst=/claws,readonly",
                repo_root.join("claws").display()
            ),
            "--tmpfs",
            "/tmp:rw,nosuid,nodev",
            "--tmpfs",
            "/phase0-home:rw,nosuid,nodev",
            "--workdir",
            "/project/admin/rust",
            "--env",
            "HOME=/phase0-home",
            "--env",
            "CARGO_HOME=/phase0-cargo",
            "--env",
            "RUSTUP_HOME=/phase0-rustup",
            "--env",
            "CARGO_TARGET_DIR=/target",
            "--env",
            "CARGO_NET_OFFLINE=true",
            "--env",
            "CARGO_INCREMENTAL=0",
            "--env",
            "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false",
            "--env",
            "PKG_CONFIG_PATH=",
            "--env",
            "PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin",
            "--env",
            "THEYOS_PHASE0_CLEAN_ENV=1",
            "--env",
            "CLAWS_CATALOG_JSON=/target/phase0-generated/claws-catalog.json",
            "--env",
            "CLAWS_MANIFEST_YML=/claws/manifest.yml",
            "--env",
            "THEYOS_EMOJI_WORDLIST=/project/admin/rust/household-rs/data/emoji-security-code-wordlist.csv",
            "--env",
            &format!("RUSTUP_TOOLCHAIN={rust_version}"),
            "--env",
            &format!("THEYOS_BUILD_GIT_SHA={source_sha}"),
            image,
            "cargo",
        ])
        .args(build_args);
    command
        .status()
        .map_err(|error| format!("failed to launch direct OCI Phase 0 build: {error}"))
}

fn canonical_value(values: &[(OsString, OsString)], name: &str) -> Result<String, String> {
    values
        .iter()
        .find_map(|(candidate, value)| {
            (candidate == name).then(|| value.to_string_lossy().into_owned())
        })
        .ok_or_else(|| format!("canonical build environment is missing {name}"))
}

fn executable_from_path(name: &str) -> Result<PathBuf, String> {
    let path = env::var_os("PATH").ok_or("canonical PATH is missing")?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file()
            && candidate
                .metadata()
                .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
        {
            return candidate
                .canonicalize()
                .map_err(|error| format!("failed to resolve {name}: {error}"));
        }
    }
    Err(format!(
        "canonical PATH does not contain executable: {name}"
    ))
}

fn reject_ancestor_cargo_configs(repo_root: &Path) -> Result<(), String> {
    for relative in [
        ".cargo/config",
        ".cargo/config.toml",
        "admin/.cargo/config",
        "admin/.cargo/config.toml",
        "admin/rust/.cargo/config",
    ] {
        let path = repo_root.join(relative);
        if fs::symlink_metadata(&path).is_ok() {
            return Err(format!(
                "canonical theyos-engine build forbids ancestor Cargo config: {relative}"
            ));
        }
    }
    let mut ancestor = repo_root.parent();
    while let Some(directory) = ancestor {
        for relative in [".cargo/config", ".cargo/config.toml"] {
            if fs::symlink_metadata(directory.join(relative)).is_ok() {
                return Err(
                    "canonical theyos-engine build forbids Cargo config above the repository"
                        .to_owned(),
                );
            }
        }
        ancestor = directory.parent();
    }
    Ok(())
}

fn reject_cargo_home_config() -> Result<(), String> {
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    let Some(cargo_home) = cargo_home else {
        return Ok(());
    };
    for name in ["config", "config.toml"] {
        let path = cargo_home.join(name);
        if fs::symlink_metadata(&path).is_ok() {
            return Err(format!(
                "canonical theyos-engine build forbids Cargo home config: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn expected_rust_version(path: &Path) -> Result<String, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    contents
        .lines()
        .find_map(|line| {
            let value = line.trim().strip_prefix("channel = \"")?;
            value.strip_suffix('"').map(str::to_owned)
        })
        .ok_or_else(|| format!("{} does not declare a Rust channel", path.display()))
}

fn command_stdout(command: &mut Command) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|error| format!("failed to launch command: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| "command output was not UTF-8".to_owned())
}

fn stage_engine(source_dir: &Path, destination: &Path) -> Result<(), String> {
    let source = source_dir.join("server");
    require_executable_regular_file(&source)?;

    let parent = destination
        .parent()
        .ok_or_else(|| format!("destination has no parent: {}", destination.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    if let Ok(metadata) = fs::symlink_metadata(destination)
        && (!metadata.file_type().is_file() || metadata.file_type().is_symlink())
    {
        return Err(format!(
            "staged destination is not a regular file: {}",
            destination.display()
        ));
    }

    let file_name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            format!(
                "destination name is not valid Unicode: {}",
                destination.display()
            )
        })?;
    let temporary = parent.join(format!(".{file_name}.stage-{}", std::process::id()));
    let result = write_staged_copy(&source, &temporary).and_then(|()| {
        if !files_equal(&source, &temporary)? {
            return Err("staged theyos-engine differs from server-rs/server".to_owned());
        }
        if destination.exists() {
            fs::remove_file(destination)
                .map_err(|error| format!("failed to replace {}: {error}", destination.display()))?;
        }
        fs::rename(&temporary, destination).map_err(|error| {
            format!(
                "failed to publish {} as {}: {error}",
                temporary.display(),
                destination.display()
            )
        })?;
        Ok(())
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;

    println!(
        "Staged server-rs production binary as theyos-engine: {}",
        destination.display()
    );
    Ok(())
}

fn require_executable_regular_file(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "required executable is missing at {}: {error}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(format!(
            "required executable is not a regular executable file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn write_staged_copy(source: &Path, temporary: &Path) -> Result<(), String> {
    let mut input = File::open(source)
        .map_err(|error| format!("failed to open {}: {error}", source.display()))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(temporary)
        .map_err(|error| format!("failed to create {}: {error}", temporary.display()))?;
    io::copy(&mut input, &mut output)
        .map_err(|error| format!("failed to stage {}: {error}", source.display()))?;
    output
        .set_permissions(fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("failed to chmod {}: {error}", temporary.display()))?;
    output
        .flush()
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("failed to flush {}: {error}", temporary.display()))
}

fn files_equal(left: &Path, right: &Path) -> Result<bool, String> {
    let left_file =
        File::open(left).map_err(|error| format!("failed to open {}: {error}", left.display()))?;
    let right_file = File::open(right)
        .map_err(|error| format!("failed to open {}: {error}", right.display()))?;
    if left_file
        .metadata()
        .map_err(|error| error.to_string())?
        .len()
        != right_file
            .metadata()
            .map_err(|error| error.to_string())?
            .len()
    {
        return Ok(false);
    }

    let mut left_reader = BufReader::new(left_file);
    let mut right_reader = BufReader::new(right_file);
    let mut left_buffer = vec![0_u8; 64 * 1024];
    let mut right_buffer = vec![0_u8; 64 * 1024];
    loop {
        let left_read = left_reader
            .read(&mut left_buffer)
            .map_err(|error| error.to_string())?;
        let right_read = right_reader
            .read(&mut right_buffer)
            .map_err(|error| error.to_string())?;
        if left_read != right_read || left_buffer[..left_read] != right_buffer[..right_read] {
            return Ok(false);
        }
        if left_read == 0 {
            return Ok(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::process::Command;

    use super::{apply_canonical_environment, is_unsafe_build_env};

    #[test]
    fn build_environment_rejects_target_and_toolchain_overrides() {
        for name in [
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS",
            "AARCH64_UNKNOWN_LINUX_MUSL_CC",
            "CROSS_CONFIG",
            "DOCKER_OPTS",
            "MACOSX_DEPLOYMENT_TARGET",
            "PKG_CONFIG_AARCH64_UNKNOWN_LINUX_MUSL",
        ] {
            assert!(is_unsafe_build_env(name), "missed {name}");
        }
        assert!(!is_unsafe_build_env("CARGO_HOME"));
        assert!(!is_unsafe_build_env("CARGO_TARGET_DIR"));
        assert!(!is_unsafe_build_env("PKG_CONFIG_PATH"));
        assert!(!is_unsafe_build_env("RUSTUP_TOOLCHAIN"));
    }

    #[test]
    fn child_process_environment_is_positive_allowlist() {
        let allowed = vec![
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            (OsString::from("CARGO_NET_OFFLINE"), OsString::from("true")),
        ];
        let mut command = Command::new("env");
        command.env("OPENSSL_DIR", "/tmp/untrusted-openssl");
        command.env("LD_PRELOAD", "/tmp/untrusted-preload.so");
        apply_canonical_environment(&mut command, &allowed);

        let explicit: Vec<_> = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|entry| entry.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(
            explicit,
            vec![
                ("CARGO_NET_OFFLINE".to_owned(), Some("true".to_owned())),
                ("PATH".to_owned(), Some("/usr/bin:/bin".to_owned())),
            ]
        );
    }
}
