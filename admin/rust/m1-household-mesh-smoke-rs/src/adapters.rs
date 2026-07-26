use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::Deserialize;
use ureq::{Agent, AgentBuilder, Error as UreqError, Response};

use crate::runner::{
    AdapterError, Authorization, ChallengeSource, ContentType, EchoReply, HostInspector, HttpProbe,
    HttpReply, LocalOs, Machines, OwnerSigner, PeerEndpoint, PeerSource, Role,
};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(2);
const PROCESS_GROUP_SHUTDOWN_GRACE: Duration = Duration::from_millis(250);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const SMALL_PROCESS_CAP: usize = 512;
const SIGNER_STDOUT_CAP: usize = 8 * 1024;
const SIGNER_ARGV_JSON_CAP: usize = 16 * 1024;
const READY_BODY_CAP: usize = 4 * 1024;
const MACHINES_BODY_CAP: usize = 64 * 1024;
const ECHO_BODY_CAP: usize = 32;
const LEGACY_SIGNER_ENV: &str = "THEYOS_HH_POP_SIGNER_CMD";
const SIGNER_V1_ENV: &str = "THEYOS_HH_POP_SIGNER_ARGV_JSON_V1";
const MACHINES_PATH: &str = "/api/v1/household/machines";

pub(crate) struct ProductionServices {
    agent: Agent,
}

impl ProductionServices {
    pub(crate) fn new() -> Self {
        Self {
            agent: AgentBuilder::new()
                .try_proxy_from_env(false)
                .redirects(0)
                .timeout_connect(HTTP_TIMEOUT)
                .timeout_read(HTTP_TIMEOUT)
                .timeout_write(HTTP_TIMEOUT)
                .build(),
        }
    }
}

impl HostInspector for ProductionServices {
    fn local_os(&mut self) -> Result<LocalOs, AdapterError> {
        Ok(match env::consts::OS {
            "macos" => LocalOs::Mac,
            "linux" => LocalOs::Linux,
            _ => LocalOs::Other,
        })
    }

    fn local_tailnet_ipv4(&mut self) -> Result<Ipv4Addr, AdapterError> {
        let mut command = Command::new("tailscale");
        command.args(["ip", "-4"]);
        let output = run_bounded(&mut command, PROCESS_TIMEOUT, SMALL_PROCESS_CAP)?;
        parse_single_tailnet_ipv4(&output)
    }

    fn mac_dev_boundary_isolated(&mut self) -> Result<bool, AdapterError> {
        for variable in [
            "SOYEHT_PROFILE_NAMESPACE",
            "THEYOS_PROFILE_NAMESPACE",
            "SOYEHT_PROFILE",
            "THEYOS_PROFILE",
        ] {
            if let Some(value) = env::var_os(variable) {
                if value != OsStr::new("SoyehtDev") {
                    return Ok(false);
                }
            }
        }

        let home = env::var_os("HOME").ok_or(AdapterError::Unavailable)?;
        let namespace = PathBuf::from(home).join("Library/Application Support/SoyehtDev");
        if !namespace.is_dir() {
            return Ok(false);
        }

        let mut command = Command::new("plutil");
        command.args([
            "-extract",
            "CFBundleIdentifier",
            "raw",
            "/Applications/Soyeht Dev.app/Contents/Info.plist",
        ]);
        let output = run_bounded(&mut command, PROCESS_TIMEOUT, SMALL_PROCESS_CAP)?;
        Ok(output == b"com.soyeht.mac.dev\n" || output == b"com.soyeht.mac.dev")
    }
}

impl PeerSource for ProductionServices {
    fn peer_endpoint(&mut self) -> Result<PeerEndpoint, AdapterError> {
        let value = env::var("M1_PEER_BASE_URL").map_err(|_| AdapterError::Invalid)?;
        PeerEndpoint::parse(&value)
    }
}

impl OwnerSigner for ProductionServices {
    fn sign_machines_request(&mut self, role: Role) -> Result<Authorization, AdapterError> {
        sign_from_environment(&SystemEnvironment, role, |config, signer_role| {
            run_signer(config, signer_role, PROCESS_TIMEOUT)
        })
    }
}

impl ChallengeSource for ProductionServices {
    fn fill_challenge(&mut self, challenge: &mut [u8; 32]) -> Result<(), AdapterError> {
        OsRng
            .try_fill_bytes(challenge)
            .map_err(|_| AdapterError::Unavailable)
    }
}

impl HttpProbe for ProductionServices {
    fn bootstrap_state(&mut self, role: Role) -> Result<HttpReply<bool>, AdapterError> {
        let url = match role {
            Role::Mac => "http://127.0.0.1:8101/bootstrap/status",
            Role::Linux => "http://127.0.0.1:8091/bootstrap/status",
        };
        let response = request_response(self.agent.get(url).call())?;
        let status = response.status();
        let body = read_bounded(response, READY_BODY_CAP)?;
        let parsed: BootstrapStatus =
            serde_json::from_slice(&body).map_err(|_| AdapterError::Invalid)?;
        Ok(HttpReply {
            status,
            body: parsed.state == BootstrapState::Ready,
        })
    }

    fn machines(
        &mut self,
        role: Role,
        authorization: &Authorization,
    ) -> Result<HttpReply<Machines>, AdapterError> {
        let url = match role {
            Role::Mac => "http://127.0.0.1:8101/api/v1/household/machines",
            Role::Linux => "http://127.0.0.1:8091/api/v1/household/machines",
        };
        let response = request_response(
            self.agent
                .get(url)
                .set("Authorization", authorization.expose_to_http())
                .call(),
        )?;
        let status = response.status();
        let body = read_bounded(response, MACHINES_BODY_CAP)?;
        let parsed = serde_json::from_slice(&body).map_err(|_| AdapterError::Invalid)?;
        Ok(HttpReply {
            status,
            body: parsed,
        })
    }

    fn echo(
        &mut self,
        peer: &PeerEndpoint,
        challenge: &[u8; 32],
    ) -> Result<EchoReply, AdapterError> {
        let url = peer.echo_url();
        let response = request_response(
            self.agent
                .post(url.as_str())
                .set("Content-Type", "application/octet-stream")
                .send_bytes(challenge),
        )?;
        let status = response.status();
        let content_type = parse_content_type(response.header("Content-Type"));
        let content_length = response
            .header("Content-Length")
            .and_then(|value| value.parse::<u64>().ok());
        let body = read_bounded(response, ECHO_BODY_CAP)?;
        Ok(EchoReply {
            status,
            content_type,
            content_length,
            body,
        })
    }
}

fn request_response(result: Result<Response, UreqError>) -> Result<Response, AdapterError> {
    match result {
        Ok(response) | Err(UreqError::Status(_, response)) => Ok(response),
        Err(UreqError::Transport(_)) => Err(AdapterError::Unavailable),
    }
}

fn read_bounded(response: Response, cap: usize) -> Result<Vec<u8>, AdapterError> {
    if response
        .header("Content-Length")
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > cap as u64)
    {
        return Err(AdapterError::TooLarge);
    }
    let limit = u64::try_from(cap)
        .map_err(|_| AdapterError::TooLarge)?
        .saturating_add(1);
    let mut body = Vec::with_capacity(cap.min(4096));
    response
        .into_reader()
        .take(limit)
        .read_to_end(&mut body)
        .map_err(|_| AdapterError::Unavailable)?;
    if body.len() > cap {
        return Err(AdapterError::TooLarge);
    }
    Ok(body)
}

fn parse_content_type(value: Option<&str>) -> ContentType {
    match value {
        Some(value) if value.eq_ignore_ascii_case("application/octet-stream") => {
            ContentType::OctetStream
        }
        Some(_) | None => ContentType::Other,
    }
}

fn parse_single_tailnet_ipv4(output: &[u8]) -> Result<Ipv4Addr, AdapterError> {
    let text = std::str::from_utf8(output).map_err(|_| AdapterError::Invalid)?;
    let mut lines = text.lines().filter(|line| !line.is_empty());
    let value = lines.next().ok_or(AdapterError::Invalid)?;
    if lines.next().is_some()
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(AdapterError::Invalid);
    }
    Ipv4Addr::from_str(value).map_err(|_| AdapterError::Invalid)
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum BootstrapState {
    Ready,
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct BootstrapStatus {
    state: BootstrapState,
}

trait Environment {
    fn contains(&self, name: &'static str) -> bool;
    fn read_unicode(&self, name: &'static str) -> Result<Option<String>, AdapterError>;
}

struct SystemEnvironment;

impl Environment for SystemEnvironment {
    fn contains(&self, name: &'static str) -> bool {
        env::var_os(name).is_some()
    }

    fn read_unicode(&self, name: &'static str) -> Result<Option<String>, AdapterError> {
        match env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(env::VarError::NotUnicode(_)) => Err(AdapterError::Invalid),
        }
    }
}

struct SignerConfig {
    executable: PathBuf,
    arguments: Vec<String>,
}

struct SignerArgv {
    executable: String,
    arguments: Vec<String>,
}

impl SignerArgv {
    fn parse(encoded: &str) -> Result<Self, AdapterError> {
        if encoded.len() > SIGNER_ARGV_JSON_CAP {
            return Err(AdapterError::TooLarge);
        }
        let mut argv: Vec<String> =
            serde_json::from_str(encoded).map_err(|_| AdapterError::Invalid)?;
        if argv.is_empty()
            || argv
                .iter()
                .any(|value| value.is_empty() || value.contains('\0'))
        {
            return Err(AdapterError::Invalid);
        }
        let executable = argv.remove(0);
        Ok(Self {
            executable,
            arguments: argv,
        })
    }
}

impl SignerConfig {
    fn from_environment(environment: &impl Environment) -> Result<Self, AdapterError> {
        if environment.contains(LEGACY_SIGNER_ENV) {
            return Err(AdapterError::Invalid);
        }
        let encoded = environment
            .read_unicode(SIGNER_V1_ENV)?
            .ok_or(AdapterError::Unavailable)?;
        let argv = SignerArgv::parse(&encoded)?;
        let executable = PathBuf::from(argv.executable);
        if !executable.is_absolute() {
            return Err(AdapterError::Invalid);
        }
        let metadata = fs::symlink_metadata(&executable).map_err(|_| AdapterError::Unavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(AdapterError::Invalid);
        }
        let canonical = fs::canonicalize(&executable).map_err(|_| AdapterError::Unavailable)?;
        if canonical != executable
            || !metadata.is_file()
            || metadata.permissions().mode() & 0o111 == 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(AdapterError::Invalid);
        }
        Ok(Self {
            executable: canonical,
            arguments: argv.arguments,
        })
    }
}

fn sign_from_environment(
    environment: &impl Environment,
    role: Role,
    mut launch: impl FnMut(&SignerConfig, Role) -> Result<Authorization, AdapterError>,
) -> Result<Authorization, AdapterError> {
    let config = SignerConfig::from_environment(environment)?;
    launch(&config, role)
}

fn run_signer(
    config: &SignerConfig,
    role: Role,
    timeout: Duration,
) -> Result<Authorization, AdapterError> {
    let mut command = signer_command(config, role);
    let output = run_bounded(&mut command, timeout, SIGNER_STDOUT_CAP)?;
    parse_authorization(output)
}

fn signer_command(config: &SignerConfig, role: Role) -> Command {
    let target_alias = match role {
        Role::Mac => "mac-alpha",
        Role::Linux => "linux-alpha",
    };
    let mut command = Command::new(&config.executable);
    command
        .args(&config.arguments)
        .env_clear()
        .env("THEYOS_HH_SIGN_METHOD", "GET")
        .env("THEYOS_HH_SIGN_PATH", MACHINES_PATH)
        .env("THEYOS_HH_SIGN_TARGET_ALIAS", target_alias);
    command
}

fn parse_authorization(mut output: Vec<u8>) -> Result<Authorization, AdapterError> {
    if output.last() != Some(&b'\n') {
        return Err(AdapterError::Invalid);
    }
    output.pop();
    if output.is_empty()
        || output
            .iter()
            .any(|byte| *byte == b'\r' || *byte == b'\n' || byte.is_ascii_control())
    {
        return Err(AdapterError::Invalid);
    }
    let text = String::from_utf8(output).map_err(|_| AdapterError::Invalid)?;
    let value = text
        .strip_prefix("Authorization: ")
        .unwrap_or(text.as_str());
    let Some(token) = value.strip_prefix("Soyeht-PoP ") else {
        return Err(AdapterError::Invalid);
    };
    let mut parts = token.split(':');
    let parsed = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    );
    let valid_structure = matches!(
        parsed,
        (Some("v1"), Some(person), Some(timestamp), Some(signature), None)
            if person.starts_with("p_")
                && person.len() > 2
                && !timestamp.is_empty()
                && timestamp.bytes().all(|byte| byte.is_ascii_digit())
                && timestamp.parse::<u64>().is_ok()
    );
    let valid_signature = match parsed {
        (_, _, _, Some(signature), _) => URL_SAFE_NO_PAD
            .decode(signature)
            .ok()
            .filter(|decoded| decoded.len() == 64)
            .is_some_and(|decoded| URL_SAFE_NO_PAD.encode(decoded) == signature),
        _ => false,
    };
    if !valid_structure
        || !valid_signature
        || !value.bytes().all(|byte| (b' '..=b'~').contains(&byte))
    {
        return Err(AdapterError::Invalid);
    }
    Ok(Authorization::from_validated(value.to_owned()))
}

fn run_bounded(
    command: &mut Command,
    timeout: Duration,
    stdout_cap: usize,
) -> Result<Vec<u8>, AdapterError> {
    run_bounded_observed(command, timeout, stdout_cap, |_| {})
}

fn run_bounded_observed(
    command: &mut Command,
    timeout: Duration,
    stdout_cap: usize,
    after_spawn: impl FnOnce(u32),
) -> Result<Vec<u8>, AdapterError> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = command.spawn().map_err(|_| AdapterError::Unavailable)?;
    after_spawn(child.id());
    let Ok(group_id) = i32::try_from(child.id()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(AdapterError::Unavailable);
    };
    let Some(mut stdout) = child.stdout.take() else {
        terminate_process_group(&mut child, group_id, false)?;
        return Err(AdapterError::Unavailable);
    };
    if set_nonblocking(&stdout).is_err() {
        terminate_process_group(&mut child, group_id, false)?;
        return Err(AdapterError::Unavailable);
    }
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        terminate_process_group(&mut child, group_id, false)?;
        return Err(AdapterError::Invalid);
    };
    let mut output = Vec::with_capacity(stdout_cap.min(4096));

    loop {
        if let Err(error) = drain_stdout(&mut stdout, &mut output, stdout_cap) {
            terminate_process_group(&mut child, group_id, false)?;
            return Err(error);
        }
        let Ok(status) = child.try_wait() else {
            terminate_process_group(&mut child, group_id, false)?;
            return Err(AdapterError::Unavailable);
        };
        match status {
            Some(status) => {
                terminate_process_group(&mut child, group_id, true)?;
                finish_capture(&mut stdout, &mut output, stdout_cap)?;
                return finish_status(status, output);
            }
            None if Instant::now() >= deadline => {
                terminate_process_group(&mut child, group_id, false)?;
                return Err(AdapterError::TimedOut);
            }
            None => thread::sleep(PROCESS_POLL_INTERVAL),
        }
    }
}

fn finish_status(status: ExitStatus, output: Vec<u8>) -> Result<Vec<u8>, AdapterError> {
    if status.success() {
        Ok(output)
    } else {
        Err(AdapterError::Unavailable)
    }
}

fn finish_capture(
    stdout: &mut ChildStdout,
    output: &mut Vec<u8>,
    stdout_cap: usize,
) -> Result<(), AdapterError> {
    let deadline = Instant::now()
        .checked_add(PROCESS_GROUP_SHUTDOWN_GRACE)
        .ok_or(AdapterError::Invalid)?;
    loop {
        match drain_stdout(stdout, output, stdout_cap)? {
            DrainState::Eof => return Ok(()),
            DrainState::Pending if Instant::now() >= deadline => {
                return Err(AdapterError::TimedOut);
            }
            DrainState::Pending => thread::sleep(PROCESS_POLL_INTERVAL),
        }
    }
}

enum DrainState {
    Eof,
    Pending,
}

fn drain_stdout(
    stdout: &mut ChildStdout,
    output: &mut Vec<u8>,
    stdout_cap: usize,
) -> Result<DrainState, AdapterError> {
    let mut chunk = [0_u8; 1024];
    loop {
        match stdout.read(&mut chunk) {
            Ok(0) => return Ok(DrainState::Eof),
            Ok(read) => {
                let Some(new_len) = output.len().checked_add(read) else {
                    return Err(AdapterError::TooLarge);
                };
                if new_len > stdout_cap {
                    return Err(AdapterError::TooLarge);
                }
                output.extend_from_slice(&chunk[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(DrainState::Pending);
            }
            Err(_) => return Err(AdapterError::Unavailable),
        }
    }
}

fn terminate_process_group(
    child: &mut Child,
    group_id: i32,
    direct_child_reaped: bool,
) -> Result<(), AdapterError> {
    let group_signal = signal_process_group(group_id);
    if !direct_child_reaped {
        let _ = child.kill();
        let deadline = Instant::now()
            .checked_add(PROCESS_GROUP_SHUTDOWN_GRACE)
            .ok_or(AdapterError::Invalid)?;
        loop {
            match child.try_wait().map_err(|_| AdapterError::Unavailable)? {
                Some(_) => break,
                None if Instant::now() >= deadline => return Err(AdapterError::TimedOut),
                None => thread::sleep(PROCESS_POLL_INTERVAL),
            }
        }
    }
    let deadline = Instant::now()
        .checked_add(PROCESS_GROUP_SHUTDOWN_GRACE)
        .ok_or(AdapterError::Invalid)?;
    loop {
        if !process_group_exists(group_id)? {
            return Ok(());
        }
        group_signal.as_ref().map_err(|error| *error)?;
        if Instant::now() >= deadline {
            return Err(AdapterError::TimedOut);
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

#[allow(unsafe_code)]
fn set_nonblocking(stdout: &ChildStdout) -> Result<(), AdapterError> {
    let descriptor = stdout.as_raw_fd();
    // SAFETY: fcntl only reads/updates flags for the valid descriptor borrowed
    // from ChildStdout; ownership and lifetime stay with the Rust value.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(AdapterError::Unavailable);
    }
    // SAFETY: the descriptor remains valid and O_NONBLOCK is a file-status
    // flag supported for the child pipe.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(AdapterError::Unavailable);
    }
    Ok(())
}

#[allow(unsafe_code)]
fn signal_process_group(group_id: i32) -> Result<(), AdapterError> {
    // SAFETY: the negative PID targets only the dedicated process group that
    // CommandExt::process_group(0) created for this child.
    if unsafe { libc::kill(-group_id, libc::SIGKILL) } == 0 {
        return Ok(());
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Ok(()),
        Some(_) | None => Err(AdapterError::Unavailable),
    }
}

#[allow(unsafe_code)]
fn process_group_exists(group_id: i32) -> Result<bool, AdapterError> {
    // SAFETY: signal 0 performs existence/permission checking only.
    if unsafe { libc::kill(-group_id, 0) } == 0 {
        return Ok(true);
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        Some(_) | None => Err(AdapterError::Unavailable),
    }
}

#[cfg(test)]
mod tests {
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
        let authorization =
            run_signer(&config, Role::Linux, Duration::from_secs(2)).expect("signer");
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
        let source =
            fs::canonicalize(executable(&["/usr/bin/printf", "/bin/printf"])).expect("source");
        let secure = directory.join("secure-signer");
        fs::copy(source, &secure).expect("copy signer fixture");
        fs::set_permissions(&secure, fs::Permissions::from_mode(0o755))
            .expect("secure permissions");

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
}
