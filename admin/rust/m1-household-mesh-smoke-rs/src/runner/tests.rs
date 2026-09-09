#![cfg(test)]

use std::io;
use std::net::Ipv4Addr;

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Effect {
    Os,
    Tailnet,
    DevBoundary,
    Ready,
    Peer,
    Signer,
    Machines,
    Challenge,
    Echo,
}

struct FakeServices {
    effects: Vec<Effect>,
    os: Result<LocalOs, AdapterError>,
    tailnet: Result<Ipv4Addr, AdapterError>,
    dev_boundary: Result<bool, AdapterError>,
    ready: Result<HttpReply<bool>, AdapterError>,
    peer: Result<PeerEndpoint, AdapterError>,
    signer: Result<Authorization, AdapterError>,
    machines: Result<HttpReply<Machines>, AdapterError>,
    challenge: Result<[u8; ECHO_BYTES], AdapterError>,
    echo: Result<EchoReply, AdapterError>,
}

impl FakeServices {
    fn passing(role: Role) -> Self {
        let (self_platform, peer_platform) = match role {
            Role::Mac => (Platform::Mac, Platform::Linux),
            Role::Linux => (Platform::Linux, Platform::Mac),
        };
        Self {
            effects: Vec::new(),
            os: Ok(match role {
                Role::Mac => LocalOs::Mac,
                Role::Linux => LocalOs::Linux,
            }),
            tailnet: Ok(Ipv4Addr::new(100, 64, 0, 10)),
            dev_boundary: Ok(true),
            ready: Ok(HttpReply {
                status: 200,
                body: true,
            }),
            peer: PeerEndpoint::parse("http://100.64.0.10:8091"),
            signer: Ok(Authorization::from_validated(
                "Soyeht-PoP v1:p_alpha:123:fixture".to_owned(),
            )),
            machines: Ok(HttpReply {
                status: 200,
                body: Machines {
                    v: 1,
                    machines: vec![
                        MachineEntry {
                            platform: self_platform,
                            is_self: true,
                            online: Some(true),
                        },
                        MachineEntry {
                            platform: peer_platform,
                            is_self: false,
                            online: Some(true),
                        },
                    ],
                },
            }),
            challenge: Ok([0x5a; ECHO_BYTES]),
            echo: Ok(EchoReply {
                status: 200,
                content_type: ContentType::OctetStream,
                content_length: Some(ECHO_BYTES as u64),
                body: vec![0x5a; ECHO_BYTES],
            }),
        }
    }
}

impl HostInspector for FakeServices {
    fn local_os(&mut self) -> Result<LocalOs, AdapterError> {
        self.effects.push(Effect::Os);
        self.os
    }

    fn local_tailnet_ipv4(&mut self) -> Result<Ipv4Addr, AdapterError> {
        self.effects.push(Effect::Tailnet);
        self.tailnet
    }

    fn mac_dev_boundary_isolated(&mut self) -> Result<bool, AdapterError> {
        self.effects.push(Effect::DevBoundary);
        self.dev_boundary
    }
}

impl HttpProbe for FakeServices {
    fn bootstrap_state(&mut self, _role: Role) -> Result<HttpReply<bool>, AdapterError> {
        self.effects.push(Effect::Ready);
        self.ready.take_for_test()
    }

    fn machines(
        &mut self,
        _role: Role,
        _authorization: &Authorization,
    ) -> Result<HttpReply<Machines>, AdapterError> {
        self.effects.push(Effect::Machines);
        self.machines.take_for_test()
    }

    fn echo(
        &mut self,
        _peer: &PeerEndpoint,
        _challenge: &[u8; ECHO_BYTES],
    ) -> Result<EchoReply, AdapterError> {
        self.effects.push(Effect::Echo);
        self.echo.take_for_test()
    }
}

impl OwnerSigner for FakeServices {
    fn sign_machines_request(&mut self, _role: Role) -> Result<Authorization, AdapterError> {
        self.effects.push(Effect::Signer);
        self.signer.take_for_test()
    }
}

impl ChallengeSource for FakeServices {
    fn fill_challenge(&mut self, challenge: &mut [u8; ECHO_BYTES]) -> Result<(), AdapterError> {
        self.effects.push(Effect::Challenge);
        match self.challenge {
            Ok(value) => {
                *challenge = value;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl PeerSource for FakeServices {
    fn peer_endpoint(&mut self) -> Result<PeerEndpoint, AdapterError> {
        self.effects.push(Effect::Peer);
        self.peer.take_for_test()
    }
}

trait TakeForTest<T> {
    fn take_for_test(&mut self) -> Result<T, AdapterError>;
}

impl<T> TakeForTest<T> for Result<T, AdapterError> {
    fn take_for_test(&mut self) -> Result<T, AdapterError> {
        std::mem::replace(self, Err(AdapterError::Unavailable))
    }
}

fn run(mode: ActiveMode, role: Role, services: &mut FakeServices) -> (u8, String) {
    let mut output = Vec::new();
    let code = run_active(mode, role, services, &mut output).expect("fixture writer");
    (code, String::from_utf8(output).expect("reports are UTF-8"))
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "fixture refuses evidence",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "fixture refuses evidence",
        ))
    }
}

#[test]
fn preflight_has_only_read_only_preflight_effects() {
    let mut services = FakeServices::passing(Role::Mac);
    let (code, output) = run(ActiveMode::Preflight, Role::Mac, &mut services);
    assert_eq!(code, 0);
    assert!(output.contains("PASS M1-PREFLIGHT"));
    assert_eq!(
        services.effects,
        [
            Effect::Os,
            Effect::Tailnet,
            Effect::DevBoundary,
            Effect::Ready
        ]
    );
}

#[test]
fn active_report_write_failure_stops_at_the_first_effect() {
    let mut services = FakeServices::passing(Role::Linux);
    assert!(
        run_active(
            ActiveMode::Verify,
            Role::Linux,
            &mut services,
            &mut FailingWriter
        )
        .is_err()
    );
    assert_eq!(services.effects, [Effect::Os]);
}

#[test]
fn verify_exercises_all_gates_in_order_for_each_role() {
    for role in [Role::Mac, Role::Linux] {
        let mut services = FakeServices::passing(role);
        let (code, output) = run(ActiveMode::Verify, role, &mut services);
        assert_eq!(code, 0);
        assert!(output.contains("PASS M1-RESULT"));
        let expected = match role {
            Role::Mac => vec![
                Effect::Os,
                Effect::Tailnet,
                Effect::DevBoundary,
                Effect::Ready,
                Effect::Peer,
                Effect::Signer,
                Effect::Machines,
                Effect::Challenge,
                Effect::Echo,
            ],
            Role::Linux => vec![
                Effect::Os,
                Effect::Tailnet,
                Effect::Ready,
                Effect::Peer,
                Effect::Signer,
                Effect::Machines,
                Effect::Challenge,
                Effect::Echo,
            ],
        };
        assert_eq!(services.effects, expected);
    }
}

#[test]
fn role_mismatch_blocks_before_any_later_effect() {
    let mut services = FakeServices::passing(Role::Mac);
    services.os = Ok(LocalOs::Linux);
    let (code, _) = run(ActiveMode::Verify, Role::Mac, &mut services);
    assert_eq!(code, EXIT_BLOCKED);
    assert_eq!(services.effects, [Effect::Os]);
}

#[test]
fn non_tailnet_local_address_is_blocked() {
    let mut services = FakeServices::passing(Role::Linux);
    services.tailnet = Ok(Ipv4Addr::new(192, 0, 2, 10));
    let (code, _) = run(ActiveMode::Preflight, Role::Linux, &mut services);
    assert_eq!(code, EXIT_BLOCKED);
    assert_eq!(services.effects, [Effect::Os, Effect::Tailnet]);
}

#[test]
fn mac_dev_boundary_is_mandatory() {
    let mut services = FakeServices::passing(Role::Mac);
    services.dev_boundary = Ok(false);
    let (code, _) = run(ActiveMode::Verify, Role::Mac, &mut services);
    assert_eq!(code, EXIT_BLOCKED);
    assert_eq!(
        services.effects,
        [Effect::Os, Effect::Tailnet, Effect::DevBoundary]
    );
    assert!(!services.effects.contains(&Effect::Signer));
}

#[test]
fn not_ready_is_blocked() {
    let mut services = FakeServices::passing(Role::Linux);
    services.ready = Ok(HttpReply {
        status: 200,
        body: false,
    });
    let (code, _) = run(ActiveMode::Verify, Role::Linux, &mut services);
    assert_eq!(code, EXIT_BLOCKED);
    assert_eq!(
        services.effects,
        [Effect::Os, Effect::Tailnet, Effect::Ready]
    );
    assert!(!services.effects.contains(&Effect::Signer));
}

#[test]
fn invalid_peer_endpoint_blocks_before_signer() {
    let mut services = FakeServices::passing(Role::Linux);
    services.peer = Err(AdapterError::Invalid);
    let (code, _) = run(ActiveMode::Verify, Role::Linux, &mut services);
    assert_eq!(code, EXIT_BLOCKED);
    assert!(!services.effects.contains(&Effect::Signer));
}

#[test]
fn unavailable_signer_blocks_before_machines_query() {
    let mut services = FakeServices::passing(Role::Linux);
    services.signer = Err(AdapterError::Unavailable);
    let (code, output) = run(ActiveMode::Verify, Role::Linux, &mut services);
    assert_eq!(code, EXIT_BLOCKED);
    assert!(output.contains("BLOCKED M1-OWNER-POP"));
    assert!(!services.effects.contains(&Effect::Machines));
}

#[test]
fn machines_must_match_self_role_peer_role_and_reachability() {
    let mut services = FakeServices::passing(Role::Linux);
    let Ok(reply) = &mut services.machines else {
        panic!("fixture");
    };
    reply.body.machines[0].platform = Platform::Mac;
    reply.body.machines[1].platform = Platform::Linux;
    let (code, _) = run(ActiveMode::Verify, Role::Linux, &mut services);
    assert_eq!(code, EXIT_BLOCKED);
    assert!(!services.effects.contains(&Effect::Challenge));

    let mut services = FakeServices::passing(Role::Linux);
    let Ok(reply) = &mut services.machines else {
        panic!("fixture");
    };
    reply.body.machines[1].online = Some(false);
    let (code, _) = run(ActiveMode::Verify, Role::Linux, &mut services);
    assert_eq!(code, EXIT_BLOCKED);
}

#[test]
fn challenge_failure_is_blocked_before_echo() {
    let mut services = FakeServices::passing(Role::Linux);
    services.challenge = Err(AdapterError::Unavailable);
    let (code, _) = run(ActiveMode::Verify, Role::Linux, &mut services);
    assert_eq!(code, EXIT_BLOCKED);
    assert!(!services.effects.contains(&Effect::Echo));
}

#[test]
fn echo_transport_is_blocked_but_semantic_mismatches_fail() {
    let mut services = FakeServices::passing(Role::Linux);
    services.echo = Err(AdapterError::TimedOut);
    let (code, _) = run(ActiveMode::Verify, Role::Linux, &mut services);
    assert_eq!(code, EXIT_BLOCKED);

    let mut services = FakeServices::passing(Role::Linux);
    services.echo = Err(AdapterError::TooLarge);
    let (code, _) = run(ActiveMode::Verify, Role::Linux, &mut services);
    assert_eq!(code, EXIT_FAIL);

    let mutations: [fn(&mut EchoReply); 4] = [
        |reply| reply.status = 500,
        |reply| reply.content_type = ContentType::Other,
        |reply| reply.content_length = Some(31),
        |reply| reply.body[0] ^= 1,
    ];
    for mutate in mutations {
        let mut services = FakeServices::passing(Role::Linux);
        let Ok(reply) = &mut services.echo else {
            panic!("fixture");
        };
        mutate(reply);
        let (code, _) = run(ActiveMode::Verify, Role::Linux, &mut services);
        assert_eq!(code, EXIT_FAIL);
    }
}

#[test]
fn reports_do_not_include_values_held_by_opaque_types() {
    let mut services = FakeServices::passing(Role::Linux);
    services.signer = Ok(Authorization::from_validated(
        "Soyeht-PoP v1:p_alpha:123:do-not-print".to_owned(),
    ));
    services.peer = PeerEndpoint::parse("http://100.64.0.77:8091");
    let (code, output) = run(ActiveMode::Verify, Role::Linux, &mut services);
    assert_eq!(code, 0);
    assert!(!output.contains("do-not-print"));
    assert!(!output.contains("100.64."));
    assert!(!output.contains("http://"));
}

#[test]
fn peer_endpoint_accepts_only_literal_tailnet_http_with_explicit_port() {
    for valid in [
        "http://100.64.0.10:8091",
        "http://[fd7a:115c:a1e0::10]:8091",
    ] {
        assert!(PeerEndpoint::parse(valid).is_ok());
    }
    for invalid in [
        "https://100.64.0.10:8091",
        "http://100.64.0.10",
        "http://100.64.0.10:0",
        "http://192.0.2.10:8091",
        "http://peer.example:8091",
        "http://100.64.0.10:8091/path",
        "http://user@100.64.0.10:8091",
    ] {
        assert!(PeerEndpoint::parse(invalid).is_err());
    }
}

#[test]
fn authorization_and_endpoint_debug_are_always_redacted() {
    let authorization = Authorization::from_validated("secret".to_owned());
    let endpoint = PeerEndpoint::parse("http://100.64.0.10:8091").expect("valid");
    assert_eq!(format!("{authorization:?}"), "Authorization([REDACTED])");
    assert_eq!(format!("{endpoint:?}"), "PeerEndpoint([REDACTED])");
}

#[test]
fn machines_deserialization_discards_identifiers() {
    let body = br#"{
            "v": 1,
            "hh_id": "must-not-be-retained",
            "self_m_id": "must-not-be-retained",
            "machines": [
              {"machine_id":"must-not-be-retained","platform":"linux-alpha","is_self":true,"online":true},
              {"machine_id":"must-not-be-retained","platform":"macos","is_self":false,"online":true}
            ]
        }"#;
    let response: Machines = serde_json::from_slice(body).expect("minimal view parses");
    assert!(machines_match_role(&response, Role::Linux));
}
