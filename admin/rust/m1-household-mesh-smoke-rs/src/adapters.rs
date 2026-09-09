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
mod tests;
