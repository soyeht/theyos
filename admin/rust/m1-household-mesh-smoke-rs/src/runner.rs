use std::fmt;
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};
use url::{Host, Url};

pub(crate) const DRY_RUN_PLAN: &str = "\
M1 household mesh smoke — DRY RUN (no network requests; no state changes)

Run locally on each host; no remote-command path exists:

  1. mac-alpha:
     - read-only preflight requires /Applications/Soyeht Dev.app
     - bundle id must be com.soyeht.mac.dev
     - profile namespace must be exactly SoyehtDev
     - local Dev engine is fixed at loopback port 8101

  2. linux-alpha:
     - run only on a dedicated Linux candidate
     - local household engine is fixed at loopback port 8091

  3. each role:
     - require a local Tailscale IPv4 without printing it

  4. each role, after the manual owner ceremony:
     - GET /bootstrap/status and require state \"ready\"
     - owner-PoP GET /api/v1/household/machines
     - require self to match the local Mac/Linux role and peer to be reciprocal
     - POST one fresh, exact 32-byte challenge to the peer echo endpoint
     - require HTTP 200, application/octet-stream, length 32, exact body

The /machines query is access-controlled, but its reachability bool is not an
authenticated identity or presence claim. The echo is unauthenticated. Neither
result is membership, authority, DeviceCert presence, or VerifiedMesh evidence.

The manual iPhone/Face ID and pair-machine ceremony is driven by the operator;
bare invocation stops here.
";

const EXIT_BLOCKED: u8 = 20;
pub(crate) const EXIT_FAIL: u8 = 21;
const ECHO_BYTES: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActiveMode {
    Preflight,
    Verify,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Mac,
    Linux,
}

impl Role {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Mac => "mac",
            Self::Linux => "linux",
        }
    }

    const fn local_alias(self) -> &'static str {
        match self {
            Self::Mac => "mac-alpha",
            Self::Linux => "linux-alpha",
        }
    }

    const fn peer_alias(self) -> &'static str {
        match self {
            Self::Mac => "linux-alpha",
            Self::Linux => "mac-alpha",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalOs {
    Mac,
    Linux,
    Other,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum AdapterError {
    Unavailable,
    TimedOut,
    Invalid,
    TooLarge,
}

#[derive(Clone, Copy)]
pub(crate) enum Outcome {
    Pass,
    Blocked,
    Fail,
}

impl Outcome {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Blocked => "BLOCKED",
            Self::Fail => "FAIL",
        }
    }

    const fn exit_code(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Blocked => EXIT_BLOCKED,
            Self::Fail => EXIT_FAIL,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum CaseId {
    Host,
    DevAck,
    Tailnet,
    DevOnly,
    Ready,
    Preflight,
    Peer,
    OwnerPop,
    Machines,
    Echo32B,
    Result,
}

impl CaseId {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "M1-HOST",
            Self::DevAck => "M1-DEV-ACK",
            Self::Tailnet => "M1-TAILNET",
            Self::DevOnly => "M1-DEV-ONLY",
            Self::Ready => "M1-READY",
            Self::Preflight => "M1-PREFLIGHT",
            Self::Peer => "M1-PEER",
            Self::OwnerPop => "M1-OWNER-POP",
            Self::Machines => "M1-MACHINES",
            Self::Echo32B => "M1-ECHO-32B",
            Self::Result => "M1-RESULT",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum StaticNote {
    HostMatches,
    HostMismatch,
    DevAckMissing,
    TailnetConfigured,
    TailnetUnavailable,
    DevBoundarySelected,
    DevBoundaryUnavailable,
    Ready,
    ReadyUnavailable,
    PreflightComplete,
    PeerMissingOrInvalid,
    SignerUnavailable,
    MachinesUnreachable,
    MachinesRejected,
    MachinesInvalid,
    MachinesPassed,
    ChallengeUnavailable,
    EchoUnreachable,
    EchoStatus,
    EchoBodySize,
    EchoContentType,
    EchoContentLength,
    EchoBodyMismatch,
    EchoPassed,
    ResultPassed,
}

impl StaticNote {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::HostMatches => "role matches the local operating system",
            Self::HostMismatch => "role does not match the local operating system",
            Self::DevAckMissing => "explicit Dev-only acknowledgement is required for verification",
            Self::TailnetConfigured => "local Tailnet IPv4 is configured",
            Self::TailnetUnavailable => "local Tailscale IPv4 is unavailable",
            Self::DevBoundarySelected => {
                "exact Dev app, bundle, namespace, and loopback engine selected"
            }
            Self::DevBoundaryUnavailable => {
                "exact Dev app, bundle, namespace, or profile boundary is unavailable"
            }
            Self::Ready => "local Dev engine reports Ready",
            Self::ReadyUnavailable => "local Dev engine is unreachable or not Ready",
            Self::PreflightComplete => "read-only Dev-only preflight complete",
            Self::PeerMissingOrInvalid => {
                "peer endpoint must be a literal Tailnet IP and explicit port"
            }
            Self::SignerUnavailable => {
                "versioned external owner-PoP signer configuration is unavailable"
            }
            Self::MachinesUnreachable => "owner-PoP machines query was unreachable",
            Self::MachinesRejected => "owner-PoP machines query was not accepted",
            Self::MachinesInvalid => "two-machine diagnostic reachability did not pass",
            Self::MachinesPassed => {
                "owner-PoP query accepted; checagem diagnóstica de reachability passou na última atualização"
            }
            Self::ChallengeUnavailable => "fresh diagnostic challenge could not be generated",
            Self::EchoUnreachable => "peer diagnostic echo was unreachable",
            Self::EchoStatus => "peer diagnostic echo returned a non-success status",
            Self::EchoBodySize => "peer diagnostic echo returned the wrong body size",
            Self::EchoContentType => "peer diagnostic echo returned the wrong content type",
            Self::EchoContentLength => "peer diagnostic echo returned the wrong declared length",
            Self::EchoBodyMismatch => "peer diagnostic echo did not return the exact challenge",
            Self::EchoPassed => {
                "exact 32-byte diagnostic round trip passed; no peer identity is inferred"
            }
            Self::ResultPassed => {
                "local role passed diagnostic gates; reciprocal role report is still required"
            }
        }
    }
}

struct Reporter<'a, W> {
    role: Role,
    output: &'a mut W,
}

impl<W: Write> Reporter<'_, W> {
    fn emit(&mut self, outcome: Outcome, case_id: CaseId, note: StaticNote) -> io::Result<()> {
        writeln!(
            self.output,
            "{} {:<14} role={} local={} peer={} — {}",
            outcome.as_str(),
            case_id.as_str(),
            self.role.as_str(),
            self.role.local_alias(),
            self.role.peer_alias(),
            note.as_str()
        )
    }

    fn stop(&mut self, outcome: Outcome, case_id: CaseId, note: StaticNote) -> io::Result<u8> {
        self.emit(outcome, case_id, note)?;
        Ok(outcome.exit_code())
    }
}

pub(crate) fn report_missing_dev_ack<W: Write>(role: Role, output: &mut W) -> io::Result<u8> {
    Reporter { role, output }.stop(Outcome::Blocked, CaseId::DevAck, StaticNote::DevAckMissing)
}

pub(crate) struct Authorization(String);

impl Authorization {
    pub(crate) fn from_validated(value: String) -> Self {
        Self(value)
    }

    pub(crate) fn expose_to_http(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Authorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Authorization([REDACTED])")
    }
}

pub(crate) struct PeerEndpoint(Url);

impl PeerEndpoint {
    pub(crate) fn parse(value: &str) -> Result<Self, AdapterError> {
        let parsed = Url::parse(value).map_err(|_| AdapterError::Invalid)?;
        if parsed.scheme() != "http"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || !matches!(parsed.path(), "" | "/")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.port().is_none_or(|port| port == 0)
        {
            return Err(AdapterError::Invalid);
        }

        let is_tailnet = match parsed.host() {
            Some(Host::Ipv4(address)) => is_tailnet_ipv4(address),
            Some(Host::Ipv6(address)) => is_tailnet_ipv6(address),
            Some(Host::Domain(_)) | None => false,
        };
        if !is_tailnet {
            return Err(AdapterError::Invalid);
        }
        Ok(Self(parsed))
    }

    pub(crate) fn echo_url(&self) -> Url {
        let mut url = self.0.clone();
        url.set_path("/api/v1/household/reachability/echo");
        url
    }
}

impl fmt::Debug for PeerEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerEndpoint([REDACTED])")
    }
}

const fn is_tailnet_ipv4(address: Ipv4Addr) -> bool {
    let bits = u32::from_be_bytes(address.octets());
    bits & 0xffc0_0000 == 0x6440_0000
}

const fn is_tailnet_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
}

#[derive(Clone, Copy)]
pub(crate) enum Platform {
    Mac,
    Linux,
    Other,
}

impl<'de> Deserialize<'de> for Platform {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PlatformVisitor;

        impl Visitor<'_> for PlatformVisitor {
            type Value = Platform;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a machine platform string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(if value == "macos" {
                    Platform::Mac
                } else if value.starts_with("linux-") {
                    Platform::Linux
                } else {
                    Platform::Other
                })
            }
        }

        deserializer.deserialize_str(PlatformVisitor)
    }
}

#[derive(Deserialize)]
pub(crate) struct MachineEntry {
    pub(crate) platform: Platform,
    pub(crate) is_self: bool,
    pub(crate) online: Option<bool>,
}

#[derive(Deserialize)]
pub(crate) struct Machines {
    pub(crate) v: u8,
    pub(crate) machines: Vec<MachineEntry>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentType {
    OctetStream,
    Other,
}

pub(crate) struct HttpReply<T> {
    pub(crate) status: u16,
    pub(crate) body: T,
}

pub(crate) struct EchoReply {
    pub(crate) status: u16,
    pub(crate) content_type: ContentType,
    pub(crate) content_length: Option<u64>,
    pub(crate) body: Vec<u8>,
}

pub(crate) trait HostInspector {
    fn local_os(&mut self) -> Result<LocalOs, AdapterError>;
    fn local_tailnet_ipv4(&mut self) -> Result<Ipv4Addr, AdapterError>;
    fn mac_dev_boundary_isolated(&mut self) -> Result<bool, AdapterError>;
}

pub(crate) trait HttpProbe {
    fn bootstrap_state(&mut self, role: Role) -> Result<HttpReply<bool>, AdapterError>;
    fn machines(
        &mut self,
        role: Role,
        authorization: &Authorization,
    ) -> Result<HttpReply<Machines>, AdapterError>;
    fn echo(
        &mut self,
        peer: &PeerEndpoint,
        challenge: &[u8; ECHO_BYTES],
    ) -> Result<EchoReply, AdapterError>;
}

pub(crate) trait OwnerSigner {
    fn sign_machines_request(&mut self, role: Role) -> Result<Authorization, AdapterError>;
}

pub(crate) trait ChallengeSource {
    fn fill_challenge(&mut self, challenge: &mut [u8; ECHO_BYTES]) -> Result<(), AdapterError>;
}

pub(crate) trait PeerSource {
    fn peer_endpoint(&mut self) -> Result<PeerEndpoint, AdapterError>;
}

pub(crate) trait SmokeServices:
    HostInspector + HttpProbe + OwnerSigner + ChallengeSource + PeerSource
{
}

impl<T> SmokeServices for T where
    T: HostInspector + HttpProbe + OwnerSigner + ChallengeSource + PeerSource
{
}

pub(crate) fn run_active<S: SmokeServices, W: Write>(
    mode: ActiveMode,
    role: Role,
    services: &mut S,
    output: &mut W,
) -> io::Result<u8> {
    let mut reporter = Reporter { role, output };

    let expected_os = match role {
        Role::Mac => LocalOs::Mac,
        Role::Linux => LocalOs::Linux,
    };
    match services.local_os() {
        Ok(actual) if actual == expected_os => {
            reporter.emit(Outcome::Pass, CaseId::Host, StaticNote::HostMatches)?;
        }
        Ok(_) | Err(_) => {
            return reporter.stop(Outcome::Blocked, CaseId::Host, StaticNote::HostMismatch);
        }
    }

    match services.local_tailnet_ipv4() {
        Ok(address) if is_tailnet_ipv4(address) => {
            reporter.emit(
                Outcome::Pass,
                CaseId::Tailnet,
                StaticNote::TailnetConfigured,
            )?;
        }
        Ok(_) | Err(_) => {
            return reporter.stop(
                Outcome::Blocked,
                CaseId::Tailnet,
                StaticNote::TailnetUnavailable,
            );
        }
    }

    if role == Role::Mac {
        match services.mac_dev_boundary_isolated() {
            Ok(true) => reporter.emit(
                Outcome::Pass,
                CaseId::DevOnly,
                StaticNote::DevBoundarySelected,
            )?,
            Ok(false) | Err(_) => {
                return reporter.stop(
                    Outcome::Blocked,
                    CaseId::DevOnly,
                    StaticNote::DevBoundaryUnavailable,
                );
            }
        }
    }

    match services.bootstrap_state(role) {
        Ok(HttpReply {
            status: 200,
            body: true,
        }) => reporter.emit(Outcome::Pass, CaseId::Ready, StaticNote::Ready)?,
        Ok(_) | Err(_) => {
            return reporter.stop(
                Outcome::Blocked,
                CaseId::Ready,
                StaticNote::ReadyUnavailable,
            );
        }
    }
    reporter.emit(
        Outcome::Pass,
        CaseId::Preflight,
        StaticNote::PreflightComplete,
    )?;

    if mode == ActiveMode::Preflight {
        return Ok(0);
    }

    let Ok(peer) = services.peer_endpoint() else {
        return reporter.stop(
            Outcome::Blocked,
            CaseId::Peer,
            StaticNote::PeerMissingOrInvalid,
        );
    };
    let Ok(authorization) = services.sign_machines_request(role) else {
        return reporter.stop(
            Outcome::Blocked,
            CaseId::OwnerPop,
            StaticNote::SignerUnavailable,
        );
    };
    let machines = match services.machines(role, &authorization) {
        Ok(HttpReply { status: 200, body }) => body,
        Ok(_) => {
            return reporter.stop(
                Outcome::Blocked,
                CaseId::Machines,
                StaticNote::MachinesRejected,
            );
        }
        Err(_) => {
            return reporter.stop(
                Outcome::Blocked,
                CaseId::Machines,
                StaticNote::MachinesUnreachable,
            );
        }
    };
    if !machines_match_role(&machines, role) {
        return reporter.stop(
            Outcome::Blocked,
            CaseId::Machines,
            StaticNote::MachinesInvalid,
        );
    }
    reporter.emit(Outcome::Pass, CaseId::Machines, StaticNote::MachinesPassed)?;

    let mut challenge = [0_u8; ECHO_BYTES];
    if services.fill_challenge(&mut challenge).is_err() {
        return reporter.stop(
            Outcome::Blocked,
            CaseId::Echo32B,
            StaticNote::ChallengeUnavailable,
        );
    }
    let echo = match services.echo(&peer, &challenge) {
        Ok(echo) => echo,
        Err(AdapterError::Invalid | AdapterError::TooLarge) => {
            return reporter.stop(Outcome::Fail, CaseId::Echo32B, StaticNote::EchoBodySize);
        }
        Err(AdapterError::Unavailable | AdapterError::TimedOut) => {
            return reporter.stop(
                Outcome::Blocked,
                CaseId::Echo32B,
                StaticNote::EchoUnreachable,
            );
        }
    };
    if echo.status != 200 {
        return reporter.stop(Outcome::Fail, CaseId::Echo32B, StaticNote::EchoStatus);
    }
    if echo.body.len() != ECHO_BYTES {
        return reporter.stop(Outcome::Fail, CaseId::Echo32B, StaticNote::EchoBodySize);
    }
    if echo.content_type != ContentType::OctetStream {
        return reporter.stop(Outcome::Fail, CaseId::Echo32B, StaticNote::EchoContentType);
    }
    if echo.content_length != Some(ECHO_BYTES as u64) {
        return reporter.stop(
            Outcome::Fail,
            CaseId::Echo32B,
            StaticNote::EchoContentLength,
        );
    }
    if echo.body.as_slice() != challenge {
        return reporter.stop(Outcome::Fail, CaseId::Echo32B, StaticNote::EchoBodyMismatch);
    }
    reporter.emit(Outcome::Pass, CaseId::Echo32B, StaticNote::EchoPassed)?;
    reporter.emit(Outcome::Pass, CaseId::Result, StaticNote::ResultPassed)?;
    Ok(0)
}

fn machines_match_role(response: &Machines, role: Role) -> bool {
    if response.v != 1 || response.machines.len() != 2 {
        return false;
    }
    let mut self_entry = None;
    let mut peer_entry = None;
    for entry in &response.machines {
        let slot = if entry.is_self {
            &mut self_entry
        } else {
            &mut peer_entry
        };
        if slot.replace(entry).is_some() {
            return false;
        }
    }
    let (Some(self_entry), Some(peer_entry)) = (self_entry, peer_entry) else {
        return false;
    };
    let role_matches = match role {
        Role::Mac => {
            matches!(self_entry.platform, Platform::Mac)
                && matches!(peer_entry.platform, Platform::Linux)
        }
        Role::Linux => {
            matches!(self_entry.platform, Platform::Linux)
                && matches!(peer_entry.platform, Platform::Mac)
        }
    };
    role_matches && peer_entry.online == Some(true)
}

#[cfg(test)]
mod tests;
