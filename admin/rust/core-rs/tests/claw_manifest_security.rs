use core_rs::manifest::{self, ClawInstallability};

const CLAW_MANIFEST: &str = include_str!("../../../../claws/manifest.yml");
const INSTALL_LINUX: &str = include_str!("../../../../scripts/install-linux.sh");
const LAUNCHER_MAIN: &str = include_str!("../../launcher-rs/src/main.rs");
const SERVER_CONFIG: &str = include_str!("../../server-rs/src/config.rs");
const VM_INSTALLER_PLAN: &str = include_str!("../../vmrunner-rs/src/installer_plan.rs");
const VM_TOOLS_PLAN: &str = include_str!("../../vmrunner-rs/src/tools_plan.rs");

#[test]
fn manual_install_scripts_do_not_use_forbidden_supply_chain_patterns() {
    assert_no_forbidden_supply_chain_patterns("claws/manifest.yml", CLAW_MANIFEST);
}

#[test]
fn active_manifest_manual_shell_npm_global_installs_pin_every_package() {
    let mut entry_name = "";
    let mut tier = "";
    let mut install_template = "";
    let mut in_manual_script = false;

    for (index, line) in CLAW_MANIFEST.lines().enumerate() {
        let line_no = index + 1;
        let indent = line_indent(line);
        let trimmed = line.trim();

        if indent == 2 && trimmed.ends_with(':') && !trimmed.starts_with('#') {
            entry_name = trimmed.trim_end_matches(':');
            tier = "";
            install_template = "";
            in_manual_script = false;
            continue;
        }

        if in_manual_script && !trimmed.is_empty() && indent <= 6 {
            in_manual_script = false;
        }

        if in_manual_script {
            if tier == "available" && install_template == "manual-shell" {
                assert_npm_global_install_is_pinned(entry_name, line_no, line);
            }
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("tier:") {
            tier = value.trim().trim_matches('"');
        } else if let Some(value) = trimmed.strip_prefix("install_template:") {
            install_template = value.trim().trim_matches('"');
        } else if trimmed == "manual_script: |" {
            in_manual_script = true;
        }
    }
}

#[test]
fn active_installable_templates_render_release_safe_commands() {
    for entry in manifest::catalog() {
        if !matches!(entry.installability(), ClawInstallability::Installable) {
            continue;
        }
        let Some(install) = entry.install else {
            continue;
        };
        if entry.install_template.is_empty() {
            continue;
        }

        let steps = core_rs::templates::render(entry.install_template, install)
            .unwrap_or_else(|| panic!("{} must render {}", entry.name, entry.install_template));

        for step in steps {
            let context = format!("{}:{}:{}", entry.name, entry.install_template, step.phase);
            assert_no_forbidden_supply_chain_patterns(&context, &step.command);
            assert_npm_global_installs_are_pinned(&context, &step.command);
            assert_pipx_installs_are_pinned(&context, &step.command);
            assert_pipx_injections_are_pinned(&context, &step.command);
            assert_plain_pip_installs_are_pinned(&context, &step.command);
        }
    }
}

#[test]
fn active_vm_installer_plans_do_not_use_forbidden_supply_chain_patterns() {
    for (name, source) in [
        ("vmrunner-rs/src/installer_plan.rs", VM_INSTALLER_PLAN),
        ("vmrunner-rs/src/tools_plan.rs", VM_TOOLS_PLAN),
    ] {
        assert_no_forbidden_supply_chain_patterns(name, source);
        assert_plain_pip_installs_are_pinned_in_rust_source(name, source);
    }
}

fn assert_npm_global_install_is_pinned(entry_name: &str, line_no: usize, line: &str) {
    assert_npm_global_install_line_is_pinned(&format!("{entry_name}:{line_no}"), line);
}

fn assert_npm_global_installs_are_pinned(context: &str, source: &str) {
    for (index, line) in source.lines().enumerate() {
        assert_npm_global_install_line_is_pinned(&format!("{context}:{}", index + 1), line);
    }
}

fn assert_npm_global_install_line_is_pinned(context: &str, line: &str) {
    let Some((_, packages)) = line.split_once("npm install -g") else {
        return;
    };

    for token in packages.split_whitespace() {
        let package = token.trim_matches(|c| matches!(c, '\'' | '"' | '\\' | ';' | ','));
        if package.is_empty() || package.starts_with('-') {
            continue;
        }
        if matches!(package, "&&" | "||" | "|" | ">" | ">>" | "<") {
            break;
        }

        assert!(
            npm_package_spec_has_exact_version(package),
            "{context} npm install -g package must pin an explicit version: {package}"
        );
    }
}

fn npm_package_spec_has_exact_version(package: &str) -> bool {
    let version = if package.starts_with('@') {
        let Some(slash) = package.find('/') else {
            return false;
        };
        let Some(version_at) = package[slash + 1..].find('@') else {
            return false;
        };
        &package[slash + 1 + version_at + 1..]
    } else {
        let Some((name, version)) = package.rsplit_once('@') else {
            return false;
        };
        if name.is_empty() {
            return false;
        }
        version
    };

    !version.is_empty()
        && version != "latest"
        && version.chars().next().is_some_and(|c| c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

fn assert_pipx_installs_are_pinned(context: &str, source: &str) {
    for (index, line) in source.lines().enumerate() {
        let Some((_, args)) = line.split_once("pipx install") else {
            continue;
        };

        let Some(package) = args
            .split_whitespace()
            .map(clean_shell_token)
            .find(|token| !token.is_empty() && !token.starts_with('-'))
        else {
            panic!(
                "{context}:{} pipx install must include a package",
                index + 1
            );
        };

        assert!(
            pip_package_spec_has_exact_version(package),
            "{context}:{} pipx install package must pin an exact version: {package}",
            index + 1
        );
    }
}

fn assert_pipx_injections_are_pinned(context: &str, source: &str) {
    for (index, line) in source.lines().enumerate() {
        let Some((_, args)) = line.split_once("pipx inject") else {
            continue;
        };

        let mut positional = args
            .split_whitespace()
            .map(clean_shell_token)
            .filter(|token| !token.is_empty() && !token.starts_with('-'));
        let _venv_or_app = positional.next();

        for package in positional {
            assert!(
                pip_package_spec_has_exact_version(package),
                "{context}:{} pipx inject package must pin an exact version: {package}",
                index + 1
            );
        }
    }
}

fn assert_plain_pip_installs_are_pinned(context: &str, source: &str) {
    assert_plain_pip_install_lines_are_pinned(context, source, false);
}

fn assert_plain_pip_installs_are_pinned_in_rust_source(context: &str, source: &str) {
    assert_plain_pip_install_lines_are_pinned(context, source, true);
}

fn assert_plain_pip_install_lines_are_pinned(
    context: &str,
    source: &str,
    allow_rust_version_placeholders: bool,
) {
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        let tokens = line
            .split_whitespace()
            .map(clean_shell_token)
            .filter(|token| !token.is_empty())
            .collect::<Vec<_>>();

        let Some(args) = plain_pip_install_args(&tokens) else {
            continue;
        };

        assert_plain_pip_install_args_are_pinned(
            &format!("{context}:{}", index + 1),
            args,
            allow_rust_version_placeholders,
        );
    }
}

fn plain_pip_install_args<'a>(tokens: &'a [&str]) -> Option<&'a [&'a str]> {
    for (index, token) in tokens.iter().enumerate() {
        if is_plain_pip_command(token)
            && tokens.get(index + 1).is_some_and(|next| *next == "install")
        {
            return Some(&tokens[index + 2..]);
        }

        if is_python_command(token)
            && tokens.get(index + 1).is_some_and(|next| *next == "-m")
            && tokens.get(index + 2).is_some_and(|next| *next == "pip")
            && tokens.get(index + 3).is_some_and(|next| *next == "install")
        {
            return Some(&tokens[index + 4..]);
        }
    }

    None
}

fn assert_plain_pip_install_args_are_pinned(
    context: &str,
    args: &[&str],
    allow_rust_version_placeholders: bool,
) {
    let upgrades_pip = args.iter().any(|arg| matches!(*arg, "--upgrade" | "-U"))
        && args.iter().any(|arg| *arg == "pip");
    let mut saw_install_input = false;
    let mut index = 0;

    while index < args.len() {
        let arg = args[index];
        if command_arg_is_boundary(arg) {
            break;
        }
        if arg.starts_with('#') {
            break;
        }

        match arg {
            "-r" | "--requirement" => {
                let Some(path) = args.get(index + 1) else {
                    panic!("{context} pip install {arg} must include a reviewed requirements file");
                };
                assert_reviewed_requirements_path(context, path);
                saw_install_input = true;
                index += 2;
                continue;
            }
            "-e" | "--editable" => {
                let Some(target) = args.get(index + 1) else {
                    panic!("{context} pip install {arg} must include a reviewed local source path");
                };
                assert_reviewed_editable_target(context, target);
                saw_install_input = true;
                index += 2;
                continue;
            }
            _ => {}
        }

        if let Some(path) = arg.strip_prefix("--requirement=") {
            assert_reviewed_requirements_path(context, path);
            saw_install_input = true;
            index += 1;
            continue;
        }
        if let Some(target) = arg.strip_prefix("--editable=") {
            assert_reviewed_editable_target(context, target);
            saw_install_input = true;
            index += 1;
            continue;
        }

        if arg.starts_with('-') {
            index += 1;
            continue;
        }

        if upgrades_pip && arg == "pip" {
            saw_install_input = true;
            index += 1;
            continue;
        }

        assert!(
            pip_package_spec_has_exact_version(arg)
                || (allow_rust_version_placeholders
                    && pip_package_spec_has_rust_version_placeholder(arg)),
            "{context} pip install package must pin an exact version or use an explicit reviewed-source input: {arg}"
        );
        saw_install_input = true;
        index += 1;
    }

    assert!(
        saw_install_input,
        "{context} pip install must include an input"
    );
}

fn is_plain_pip_command(token: &str) -> bool {
    matches!(token, "pip" | "pip3") || token.ends_with("/pip") || token.ends_with("/pip3")
}

fn is_python_command(token: &str) -> bool {
    matches!(token, "python" | "python3")
        || token.ends_with("/python")
        || token.ends_with("/python3")
}

fn command_arg_is_boundary(arg: &str) -> bool {
    matches!(
        arg,
        "&&" | "||" | "|" | ">" | ">>" | "<" | "then" | "fi" | "do" | "done"
    )
}

fn assert_reviewed_requirements_path(context: &str, path: &str) {
    // Requirements installs are allowed only for local files from reviewed,
    // already checked-out source trees. Remote requirement URLs stay forbidden.
    assert!(
        !path.contains("://") && path.ends_with("requirements.txt"),
        "{context} pip install requirements input must be a reviewed local requirements.txt file: {path}"
    );
}

fn assert_reviewed_editable_target(context: &str, target: &str) {
    // Editable installs are allowed only for the reviewed local checkout in the
    // current working directory, including local extras such as .[all].
    assert!(
        target == "." || target.starts_with("./") || target.starts_with(".["),
        "{context} pip install editable input must be the reviewed local checkout: {target}"
    );
}

fn pip_package_spec_has_exact_version(package: &str) -> bool {
    let Some((name, version)) = package.split_once("==") else {
        return false;
    };
    !name.is_empty()
        && !version.is_empty()
        && version != "latest"
        && version.chars().next().is_some_and(|c| c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '!'))
}

fn pip_package_spec_has_rust_version_placeholder(package: &str) -> bool {
    let Some((name, version)) = package.split_once("==") else {
        return false;
    };
    !name.is_empty() && matches!(version, "{version}")
}

fn assert_no_forbidden_supply_chain_patterns(name: &str, source: &str) {
    for forbidden in [
        "curl -fsSL https://deb.nodesource.com/setup_22.x",
        "https://deb.nodesource.com/setup_22.x",
        "nodesource_setup.sh",
        "bash /tmp/nodesource",
        "https://sh.rustup.rs",
        "| bash",
        "| sh -",
        "| /bin/sh",
        "git clone --depth 1",
        "git clone --depth",
        "git fetch origin && git checkout",
        "git pull origin",
        "origin/HEAD",
        "--break-system-packages",
        "@latest",
        "HOST=\"${HOST:-0.0.0.0}\"",
    ] {
        for (index, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.contains(".contains(") {
                continue;
            }
            assert!(
                !line.contains(forbidden),
                "{name}:{} must not contain forbidden install pattern: {forbidden}",
                index + 1
            );
        }
    }
}

fn clean_shell_token(token: &str) -> &str {
    token.trim_matches(|c| matches!(c, '\'' | '"' | '\\' | ';' | ','))
}

fn line_indent(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count()
}

#[test]
fn manual_git_sources_fetch_reviewed_commits_explicitly() {
    for (path, commit) in [
        ("/opt/clawwork", "9c73ac05fdb0bffdb23febdd971eb70f44dd46eb"),
        (
            "/opt/claw-empire",
            "66a24ea7df2435ef897c48c147deb7ec572c01c2",
        ),
        ("/opt/rt-claw", "5811922c4886cb5e90a5908fff792665e913ca48"),
        (
            "/opt/hermitclaw",
            "2b69414969e66702f4aad50e0b09594cc26ccd11",
        ),
        ("/opt/myclaw", "7b1f24cdd292b0b532862b69957eecc036b5da19"),
        (
            "/opt/subzeroclaw",
            "1d203dd4a896b02d521b300431c9127f2917d10a",
        ),
        ("/opt/epsiclaw", "475147f68fb1fb951b2f5b8bc96b3a58f075c340"),
    ] {
        let fetch = format!("git -C {path} fetch --depth 1 origin {commit}");
        let verify = format!("test \"$(git -C {path} rev-parse HEAD)\" = \"{commit}\"");
        assert!(
            CLAW_MANIFEST.contains(&fetch),
            "manual source {path} must fetch the reviewed commit {commit}"
        );
        assert!(
            CLAW_MANIFEST.contains(&verify),
            "manual source {path} must verify the checked-out commit {commit}"
        );
    }
}

#[test]
fn node_source_repo_is_added_without_remote_shell_pipe() {
    assert!(CLAW_MANIFEST.contains("nodesource.sources"));
    assert!(CLAW_MANIFEST.contains("Signed-By: /usr/share/keyrings/nodesource.gpg"));
    assert!(CLAW_MANIFEST.contains("https://deb.nodesource.com/node_22.x"));
    assert_eq!(
        CLAW_MANIFEST
            .matches("b42e0321dabdc24e892115da705cf061167eac12a317f23d329862d0aa0a271d  /tmp/nodesource-repo.gpg.key")
            .count(),
        2,
        "Every NodeSource key download must verify the reviewed SHA-256 before gpg --dearmor"
    );
}

#[test]
fn claw_empire_defaults_to_localhost() {
    assert!(CLAW_MANIFEST.contains("HOST=\"${HOST:-127.0.0.1}\""));
}

#[test]
fn admin_http_defaults_to_loopback_not_wildcard() {
    assert!(SERVER_CONFIG.contains("const DEFAULT_ADDR: &str = \"127.0.0.1:8090\""));
    assert!(!SERVER_CONFIG.contains("\"0.0.0.0:8090\""));

    assert!(LAUNCHER_MAIN.contains("format!(\"127.0.0.1:{admin_port}\")"));
    assert!(!LAUNCHER_MAIN.contains("format!(\"0.0.0.0:{admin_port}\")"));

    assert!(INSTALL_LINUX.contains("Environment=ADDR=127.0.0.1:8892"));
    assert!(!INSTALL_LINUX.contains("Environment=ADDR=0.0.0.0:8892"));
    assert!(!INSTALL_LINUX.contains("sudo ufw allow 8892/tcp"));
    assert!(!INSTALL_LINUX.contains("sudo firewall-cmd --permanent --add-port=8892/tcp"));
}
