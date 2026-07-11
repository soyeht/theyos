use std::env;
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

const TRACKED_PKG_CONFIG_PATH: &str =
    "/nix/store/wr6qvslzqrd3rsf2mw0ssxwmyi2sqjdh-openssl-3.4.2-dev/lib/pkgconfig";

const REPO_INPUT_OVERRIDE_ENV: [&str; 3] = [
    "CLAWS_MANIFEST_YML",
    "CLAWS_CATALOG_JSON",
    "THEYOS_EMOJI_WORDLIST",
];

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
    let expected_rust = expected_rust_version(&rust_root.join("rust-toolchain.toml"))?;
    let rustc_verbose = command_stdout(Command::new("rustc").current_dir(&rust_root).arg("-vV"))?;
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

    let source_sha = match env::var("THEYOS_BUILD_GIT_SHA") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => command_stdout(
            Command::new("git")
                .arg("-C")
                .arg(&repo_root)
                .args(["rev-parse", "HEAD"]),
        )?,
        Err(env::VarError::NotUnicode(_)) => {
            return Err("THEYOS_BUILD_GIT_SHA must be valid Unicode".to_owned());
        }
    };
    if source_sha.len() != 40
        || !source_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("THEYOS_BUILD_GIT_SHA must be a full lowercase Git SHA".to_owned());
    }

    let mut build = Command::new(build_tool);
    build
        .current_dir(&rust_root)
        .args([
            "build",
            "--quiet",
            "--manifest-path",
            "Cargo.toml",
            "--locked",
            "--release",
            "--target",
            target,
            "--package",
            "server-rs",
            "--bin",
            "server",
            "--no-default-features",
        ])
        .env("THEYOS_BUILD_GIT_SHA", &source_sha)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS", "false");
    for name in REPO_INPUT_OVERRIDE_ENV {
        build.env_remove(name);
    }
    if build_tool == "cross" {
        let claws_dir = repo_root.join("claws").canonicalize().map_err(|error| {
            format!(
                "failed to resolve canonical Claw manifest directory {}: {error}",
                repo_root.join("claws").display()
            )
        })?;
        if !claws_dir.join("manifest.yml").is_file() {
            return Err(format!(
                "canonical Claw manifest is missing: {}",
                claws_dir.join("manifest.yml").display()
            ));
        }
        let claws_dir = claws_dir
            .to_str()
            .ok_or("canonical Claw manifest path is not valid Unicode")?;
        let mount = shell_word(&format!("--volume={claws_dir}:/claws:ro"));
        build.env(
            "CROSS_CONTAINER_OPTS",
            format!("{mount} --env=CLAWS_CATALOG_JSON=/tmp/theyos-claws-catalog.json"),
        );
    }
    let status = build
        .status()
        .map_err(|error| format!("failed to launch {build_tool}: {error}"))?;
    if !status.success() {
        return Err(format!(
            "canonical theyos-engine build failed for {target} with {build_tool}"
        ));
    }

    let target_root = env::var_os("CARGO_TARGET_DIR").map_or_else(
        || rust_root.join("target"),
        |value| {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                path
            } else {
                rust_root.join(path)
            }
        },
    );
    let release_dir = target_root.join(target).join("release");
    let binary = release_dir.join("server");
    let depfile = release_dir.join("server.d");
    require_executable_regular_file(&binary)?;
    if !depfile.is_file() {
        return Err(format!(
            "canonical theyos-engine build did not produce depfile: {}",
            depfile.display()
        ));
    }
    println!("{}", binary.display());
    Ok(())
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

fn shell_word(value: &str) -> String {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"%+,-./:=@_".contains(&byte))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
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
    use super::{is_unsafe_build_env, shell_word};

    #[test]
    fn shell_word_preserves_container_option_as_one_argument() {
        assert_eq!(
            shell_word("--volume=/tmp/with space/claws:/claws:ro"),
            "'--volume=/tmp/with space/claws:/claws:ro'"
        );
        assert_eq!(
            shell_word("--volume=/tmp/owner's/claws:/claws:ro"),
            "'--volume=/tmp/owner'\\''s/claws:/claws:ro'"
        );
    }

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
}
