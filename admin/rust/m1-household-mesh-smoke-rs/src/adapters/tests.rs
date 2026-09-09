#![cfg(test)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::process;
use std::rc::Rc;

use super::*;

const DESCENDANT_HELPER_ENV: &str = "M1_SMOKE_DESCENDANT_HELPER";
const DESCENDANT_PID_FILE_ENV: &str = "M1_SMOKE_DESCENDANT_PID_FILE";

struct FakeEnvironment {
    values: BTreeMap<&'static str, String>,
    reads: Rc<RefCell<Vec<&'static str>>>,
}

impl Environment for FakeEnvironment {
    fn contains(&self, name: &'static str) -> bool {
        self.reads.borrow_mut().push(name);
        self.values.contains_key(name)
    }

    fn read_unicode(&self, name: &'static str) -> Result<Option<String>, AdapterError> {
        self.reads.borrow_mut().push(name);
        Ok(self.values.get(name).cloned())
    }
}

fn executable(candidates: &[&str]) -> PathBuf {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("standard test executable")
}

fn encoded_argv(executable: &Path, args: &[&str]) -> String {
    let values: Vec<String> = std::iter::once(executable.to_string_lossy().into_owned())
        .chain(args.iter().map(|value| (*value).to_owned()))
        .collect();
    serde_json::to_string(&values).expect("fixture JSON")
}

fn authorization_line(signature_bytes: &[u8]) -> String {
    format!(
        "Soyeht-PoP v1:p_alpha:123:{}\n",
        URL_SAFE_NO_PAD.encode(signature_bytes)
    )
}

fn signer_fixture_dir(label: &str) -> PathBuf {
    let directory = env::temp_dir().join(format!("m1-smoke-signer-{}-{label}", process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).expect("create signer fixture directory");
    fs::canonicalize(directory).expect("canonical fixture directory")
}

#[test]
fn legacy_presence_blocks_before_v1_is_read() {
    let reads = Rc::new(RefCell::new(Vec::new()));
    let environment = FakeEnvironment {
        values: BTreeMap::from([
            (LEGACY_SIGNER_ENV, "must-not-be-read".to_owned()),
            (SIGNER_V1_ENV, "[\"/must/not/be/read\"]".to_owned()),
        ]),
        reads: Rc::clone(&reads),
    };
    assert!(SignerConfig::from_environment(&environment).is_err());
    assert_eq!(&*reads.borrow(), &[LEGACY_SIGNER_ENV]);
}

#[test]
fn invalid_or_legacy_configuration_never_launches_a_child() {
    for values in [
        BTreeMap::new(),
        BTreeMap::from([(SIGNER_V1_ENV, "not-json".to_owned())]),
        BTreeMap::from([(SIGNER_V1_ENV, "[\"/bin/echo\",\"\"]".to_owned())]),
        BTreeMap::from([(SIGNER_V1_ENV, "[\"/bin/echo\\u0000\"]".to_owned())]),
        BTreeMap::from([(
            SIGNER_V1_ENV,
            "[\"/bin/echo\",\"bad\\u0000argument\"]".to_owned(),
        )]),
        BTreeMap::from([(LEGACY_SIGNER_ENV, "must-not-be-read".to_owned())]),
    ] {
        let environment = FakeEnvironment {
            values,
            reads: Rc::new(RefCell::new(Vec::new())),
        };
        let mut launches = 0;
        let result = sign_from_environment(&environment, Role::Linux, |_, _| {
            launches += 1;
            Err(AdapterError::Unavailable)
        });
        assert!(result.is_err());
        assert_eq!(launches, 0);
    }
}

#[test]
fn v1_parser_rejects_empty_nul_and_non_absolute_argv_before_launch() {
    for value in [
        String::new(),
        "{}".to_owned(),
        "[]".to_owned(),
        "[1]".to_owned(),
        "[\"\"]".to_owned(),
        "[\"/bin/echo\",\"\"]".to_owned(),
        "[\"/bin/echo\\u0000\"]".to_owned(),
        "[\"/bin/echo\",\"bad\\u0000argument\"]".to_owned(),
        "x".repeat(SIGNER_ARGV_JSON_CAP + 1),
    ] {
        assert!(SignerArgv::parse(&value).is_err());
    }
    for value in [
        String::new(),
        "{}".to_owned(),
        "[]".to_owned(),
        "[1]".to_owned(),
        "[\"\"]".to_owned(),
        "[\"/bin/echo\",\"\"]".to_owned(),
        "[\"/bin/echo\\u0000\"]".to_owned(),
        "[\"/bin/echo\",\"bad\\u0000argument\"]".to_owned(),
        "[\"relative\"]".to_owned(),
        "x".repeat(SIGNER_ARGV_JSON_CAP + 1),
    ] {
        let environment = FakeEnvironment {
            values: BTreeMap::from([(SIGNER_V1_ENV, value)]),
            reads: Rc::new(RefCell::new(Vec::new())),
        };
        assert!(SignerConfig::from_environment(&environment).is_err());
    }
}

#[test]
fn strict_authorization_parser_allows_one_line_only() {
    let valid = authorization_line(&[0x5a; 64]);
    assert!(parse_authorization(valid.as_bytes().to_vec()).is_ok());
    assert!(parse_authorization(format!("Authorization: {valid}").into_bytes()).is_ok());

    let signature = URL_SAFE_NO_PAD.encode([0x5a; 64]);
    let mut noncanonical_signature = URL_SAFE_NO_PAD.encode([0_u8; 64]);
    noncanonical_signature.pop();
    noncanonical_signature.push('B');
    for invalid in [
        String::new(),
        "Bearer fixture\n".to_owned(),
        format!("Soyeht-PoP v1:p_alpha:123:{signature}"),
        format!("Soyeht-PoP v1:p_alpha:123:{signature}\n\n"),
        format!("Soyeht-PoP v1:p_alpha:123:{signature}\r\n"),
        format!("Soyeht-PoP v1:p_alpha:123:{signature}\nextra\n"),
        format!("Soyeht-PoP v1:p_alpha:123:{signature}\nextra"),
        format!("Soyeht-PoP v1:p_alpha:123:\x01{signature}\n"),
        format!("Authorization:Soyeht-PoP v1:p_alpha:123:{signature}\n"),
        format!("Soyeht-PoP v1:p_alpha:123:{signature} \n"),
        format!("Soyeht-PoP v1:not-a-person:123:{signature}\n"),
        format!("Soyeht-PoP v1:p_alpha:not-time:{signature}\n"),
        authorization_line(&[0x5a; 63]),
        authorization_line(&[0x5a; 65]),
        format!("Soyeht-PoP v1:p_alpha:123:{signature}=\n"),
        "Soyeht-PoP v1:p_alpha:123:not+url-safe\n".to_owned(),
        format!("Soyeht-PoP v1:p_alpha:123:{noncanonical_signature}\n"),
    ] {
        assert!(parse_authorization(invalid.into_bytes()).is_err());
    }
}

#[test]
fn bounded_process_rejects_excess_and_kills_then_reaps_timeout() {
    let printf = executable(&["/usr/bin/printf", "/bin/printf"]);
    let mut oversized = Command::new(&printf);
    oversized.args(["%0100d", "0"]);
    let oversized_result = run_bounded(&mut oversized, Duration::from_secs(1), 16);
    assert!(
        matches!(oversized_result, Err(AdapterError::TooLarge)),
        "unexpected oversized result: {oversized_result:?}"
    );

    let sleep = executable(&["/bin/sleep", "/usr/bin/sleep"]);
    let mut delayed = Command::new(&sleep);
    delayed.arg("5");
    let mut delayed_pid = None;
    assert!(matches!(
        run_bounded_observed(&mut delayed, Duration::from_millis(20), 16, |pid| {
            delayed_pid = Some(pid);
        }),
        Err(AdapterError::TimedOut)
    ));
    let ps = executable(&["/bin/ps", "/usr/bin/ps"]);
    let mut process_probe = Command::new(ps);
    process_probe
        .args(["-p", &delayed_pid.expect("process was spawned").to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    assert!(
        !process_probe
            .status()
            .expect("process existence probe")
            .success(),
        "timed-out child must be killed and reaped"
    );
}

#[test]
#[expect(
    clippy::zombie_processes,
    reason = "the helper must exit without waiting so the descendant holds stdout; the outer harness kills the dedicated PGID and proves the group and PID disappear"
)]
fn descendant_stdout_holder_helper() {
    if env::var_os(DESCENDANT_HELPER_ENV).is_none() {
        return;
    }
    let pid_file = env::var_os(DESCENDANT_PID_FILE_ENV).expect("PID file");
    let sleep = executable(&["/bin/sleep", "/usr/bin/sleep"]);
    let child = Command::new(sleep)
        .arg("5")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("descendant");
    fs::write(pid_file, child.id().to_string()).expect("record descendant PID");
}

#[test]
fn bounded_process_terminates_descendants_that_hold_stdout() {
    let helper = env::current_exe().expect("current test executable");
    let pid_file = env::temp_dir().join(format!(
        "m1-smoke-descendant-{}-{}.pid",
        process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    let mut command = Command::new(helper);
    command
        .args([
            "--exact",
            "adapters::tests::descendant_stdout_holder_helper",
            "--nocapture",
        ])
        .env_clear()
        .env(DESCENDANT_HELPER_ENV, "1")
        .env(DESCENDANT_PID_FILE_ENV, &pid_file);

    let mut group_id = None;
    let started = Instant::now();
    let result = run_bounded_observed(&mut command, Duration::from_secs(1), 8 * 1024, |pid| {
        group_id = i32::try_from(pid).ok();
    });
    assert!(result.is_ok(), "direct helper exits successfully");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "inherited stdout must not extend the process bound"
    );

    let descendant_pid: u32 = fs::read_to_string(&pid_file)
        .expect("descendant PID")
        .parse()
        .expect("numeric PID");
    fs::remove_file(&pid_file).expect("remove PID fixture");
    assert!(
        !process_group_exists(group_id.expect("bounded process group")).expect("group probe"),
        "dedicated process group must be gone"
    );

    let ps = executable(&["/bin/ps", "/usr/bin/ps"]);
    let status = Command::new(ps)
        .args(["-p", &descendant_pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("descendant existence probe");
    assert!(
        !status.success(),
        "descendant that inherited stdout must not survive"
    );
}

#[test]
fn signer_child_gets_only_fixed_environment_and_eof() {
    let env_program = executable(&["/usr/bin/env"]);
    let config = SignerConfig {
        executable: fs::canonicalize(env_program).expect("canonical env"),
        arguments: Vec::new(),
    };
    let mut inspect_environment = signer_command(&config, Role::Linux);
    let mut environment: Vec<(OsString, Option<OsString>)> = inspect_environment
        .get_envs()
        .map(|(key, value)| (key.to_owned(), value.map(OsStr::to_owned)))
        .collect();
    environment.sort_unstable();
    assert_eq!(
        environment,
        [
            (
                OsString::from("THEYOS_HH_SIGN_METHOD"),
                Some(OsString::from("GET"))
            ),
            (
                OsString::from("THEYOS_HH_SIGN_PATH"),
                Some(OsString::from("/api/v1/household/machines"))
            ),
            (
                OsString::from("THEYOS_HH_SIGN_TARGET_ALIAS"),
                Some(OsString::from("linux-alpha"))
            ),
        ]
    );
    let output = run_bounded(
        &mut inspect_environment,
        Duration::from_secs(1),
        SMALL_PROCESS_CAP,
    )
    .expect("environment inspection");
    let mut child_environment: Vec<&[u8]> = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    child_environment.sort_unstable();
    assert_eq!(
        child_environment,
        [
            b"THEYOS_HH_SIGN_METHOD=GET".as_slice(),
            b"THEYOS_HH_SIGN_PATH=/api/v1/household/machines".as_slice(),
            b"THEYOS_HH_SIGN_TARGET_ALIAS=linux-alpha".as_slice(),
        ]
    );
    assert!(!output.windows(5).any(|window| window == b"_CMD="));
    assert!(!output.windows(14).any(|window| window == b"_ARGV_JSON_V1="));

    let cat = executable(&["/bin/cat", "/usr/bin/cat"]);
    let eof_config = SignerConfig {
        executable: fs::canonicalize(cat).expect("canonical cat"),
        arguments: Vec::new(),
    };
    let mut inspect_stdin = signer_command(&eof_config, Role::Linux);
    assert!(
        run_bounded(&mut inspect_stdin, Duration::from_secs(1), 1)
            .expect("stdin inspection")
            .is_empty()
    );

    let printf = executable(&["/usr/bin/printf", "/bin/printf"]);
    let config = SignerConfig {
        executable: fs::canonicalize(printf).expect("canonical printf"),
        arguments: vec![format!(
            "Authorization: {}",
            authorization_line(&[0x5a; 64])
        )],
    };
    let authorization = run_signer(&config, Role::Linux, Duration::from_secs(2)).expect("signer");
    assert_eq!(format!("{authorization:?}"), "Authorization([REDACTED])");
}

#[test]
fn signer_config_resolves_an_absolute_regular_executable() {
    let printf =
        fs::canonicalize(executable(&["/usr/bin/printf", "/bin/printf"])).expect("canonical");
    let reads = Rc::new(RefCell::new(Vec::new()));
    let environment = FakeEnvironment {
        values: BTreeMap::from([(
            SIGNER_V1_ENV,
            encoded_argv(&printf, &["Soyeht-PoP v1:p_alpha:123:fixture"]),
        )]),
        reads: Rc::clone(&reads),
    };
    let config = SignerConfig::from_environment(&environment).expect("valid signer argv");
    assert!(config.executable.is_absolute());
    assert_eq!(&*reads.borrow(), &[LEGACY_SIGNER_ENV, SIGNER_V1_ENV]);

    let mut launches = 0;
    let result = sign_from_environment(&environment, Role::Linux, |_, role| {
        launches += 1;
        assert!(role == Role::Linux);
        Ok(Authorization::from_validated(
            "Soyeht-PoP v1:p_alpha:123:fixture".to_owned(),
        ))
    });
    assert!(result.is_ok());
    assert_eq!(launches, 1);
}

#[test]
fn signer_rejects_symlink_and_writable_executables_before_launch() {
    let directory = signer_fixture_dir("executable-policy");
    let source = fs::canonicalize(executable(&["/usr/bin/printf", "/bin/printf"])).expect("source");
    let secure = directory.join("secure-signer");
    fs::copy(source, &secure).expect("copy signer fixture");
    fs::set_permissions(&secure, fs::Permissions::from_mode(0o755)).expect("secure permissions");

    let symlink = directory.join("symlink-signer");
    std::os::unix::fs::symlink(&secure, &symlink).expect("signer symlink");

    let nested = directory.join("nested");
    fs::create_dir(&nested).expect("nested fixture directory");
    let noncanonical = nested.join("..").join("secure-signer");

    let group_writable = directory.join("group-writable-signer");
    fs::copy(&secure, &group_writable).expect("group-writable fixture");
    fs::set_permissions(&group_writable, fs::Permissions::from_mode(0o775))
        .expect("group-writable permissions");

    let other_writable = directory.join("other-writable-signer");
    fs::copy(&secure, &other_writable).expect("other-writable fixture");
    fs::set_permissions(&other_writable, fs::Permissions::from_mode(0o757))
        .expect("other-writable permissions");

    for executable in [symlink, noncanonical, group_writable, other_writable] {
        let environment = FakeEnvironment {
            values: BTreeMap::from([(SIGNER_V1_ENV, encoded_argv(&executable, &["arg"]))]),
            reads: Rc::new(RefCell::new(Vec::new())),
        };
        let mut launches = 0;
        let result = sign_from_environment(&environment, Role::Linux, |_, _| {
            launches += 1;
            Err(AdapterError::Unavailable)
        });
        assert!(result.is_err());
        assert_eq!(launches, 0);
    }
    fs::remove_dir_all(directory).expect("remove signer fixtures");
}

#[test]
fn process_content_never_enters_static_runner_reports() {
    let signature = URL_SAFE_NO_PAD.encode([0xa5; 64]);
    let sensitive = format!("Soyeht-PoP v1:p_alpha:123:{signature}\n").into_bytes();
    let authorization = parse_authorization(sensitive).expect("valid fixture");
    assert!(!format!("{authorization:?}").contains(&signature));
    for note in [
        crate::runner::StaticNote::SignerUnavailable,
        crate::runner::StaticNote::MachinesUnreachable,
        crate::runner::StaticNote::MachinesRejected,
    ] {
        assert!(!note.as_str().contains(&signature));
    }
}

#[test]
fn minimal_json_views_ignore_sensitive_extra_fields() {
    let ready: BootstrapStatus = serde_json::from_slice(
        br#"{"state":"ready","host_label":"do-not-retain","hh_id":"do-not-retain"}"#,
    )
    .expect("status parses");
    assert!(ready.state == BootstrapState::Ready);

    let machines: Machines = serde_json::from_slice(
        br#"{"v":1,"hh_id":"do-not-retain","machines":[
              {"machine_id":"do-not-retain","platform":"linux-alpha","is_self":true,"online":true},
              {"machine_id":"do-not-retain","platform":"macos","is_self":false,"online":true}
            ]}"#,
    )
    .expect("machines parses");
    assert_eq!(machines.machines.len(), 2);
}

#[test]
fn local_tailnet_parser_is_single_value_and_strict() {
    assert_eq!(
        parse_single_tailnet_ipv4(b"100.64.0.10\n").expect("valid"),
        Ipv4Addr::new(100, 64, 0, 10)
    );
    for invalid in [
        b"".as_slice(),
        b"100.64.0.10\n100.64.0.11\n".as_slice(),
        b"100.64.0.10 extra\n".as_slice(),
        b"not-an-address\n".as_slice(),
    ] {
        assert!(parse_single_tailnet_ipv4(invalid).is_err());
    }
}

#[test]
fn content_type_is_exact_and_case_insensitive() {
    assert!(matches!(
        parse_content_type(Some("Application/Octet-Stream")),
        ContentType::OctetStream
    ));
    assert!(matches!(
        parse_content_type(Some("application/octet-stream; charset=x")),
        ContentType::Other
    ));
}
