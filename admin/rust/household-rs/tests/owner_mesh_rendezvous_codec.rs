use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use ciborium::value::Value as CborValue;
use household_rs::{
    cbor,
    owner_mesh_rendezvous_codec::{
        self as codec, Candidate, CodecError, Endpoint, Frame, IpBytes, MAX_CANDIDATES_PER_FRAME,
        MAX_FRAME_BYTES, MAX_RELAY_CANDIDATES_PER_FRAME, MAX_SIGNED_OFFER_BYTES,
        RENDEZVOUS_ID_BYTES,
    },
};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

const CORPUS_SHA256: &str = "dacc02756a45f1a3e2744fa23dcf09926df0023c5c3992a30e55e4973b608ba0";

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn corpus_path() -> PathBuf {
    repository_root()
        .join("admin/contracts/mobile-claw-vpn/v1/owner_mesh_rendezvous_corpus_v1.json")
}

fn corpus_bytes() -> Vec<u8> {
    fs::read(corpus_path()).expect("read frozen owner-mesh rendezvous corpus")
}

fn corpus() -> JsonValue {
    serde_json::from_slice(&corpus_bytes()).expect("parse frozen rendezvous corpus JSON")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn vector_bytes(vector: &JsonValue) -> Vec<u8> {
    let encoded = vector["raw_hex"]
        .as_str()
        .or_else(|| vector["canonical_cbor_hex"].as_str())
        .expect("vector bytes must be present as raw_hex or canonical_cbor_hex");
    let bytes = hex::decode(encoded).expect("vector bytes must be lowercase, even-length hex");
    assert_eq!(
        bytes.len(),
        usize::try_from(vector["raw_length"].as_u64().expect("raw_length"))
            .expect("raw length fits usize")
    );
    assert_eq!(
        sha256_hex(&bytes),
        vector["raw_sha256_hex"].as_str().expect("raw_sha256_hex")
    );
    bytes
}

#[test]
fn frozen_corpus_raw_bytes_are_pinned() {
    let bytes = corpus_bytes();
    assert_eq!(bytes.len(), 44_179);
    assert_eq!(sha256_hex(&bytes), CORPUS_SHA256);
}

#[test]
fn all_positive_controls_decode_and_reencode_byte_exact() {
    let corpus = corpus();
    let controls = corpus["positive_controls"].as_array().expect("controls");
    assert_eq!(controls.len(), 5);

    for control in controls {
        let bytes = vector_bytes(control);
        let frame = codec::decode(&bytes).unwrap_or_else(|error| {
            panic!("{} must decode: {error}", control["id"]);
        });
        assert_eq!(codec::encode(&frame), bytes, "{}", control["id"]);

        let semantic = &control["semantic_control"];
        if let Some(kind) = semantic["kind"].as_u64() {
            assert_eq!(frame.kind(), kind);
        }
        assert_eq!(frame.rendezvous_id().as_bytes().len(), RENDEZVOUS_ID_BYTES);

        if let Some(classes) = semantic["candidate_classes"].as_array() {
            let actual = frame
                .candidates()
                .iter()
                .map(Candidate::class)
                .collect::<Vec<_>>();
            let expected = classes
                .iter()
                .map(|class| class.as_u64().expect("candidate class"))
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "{}", control["id"]);
        }
        if semantic["observed_reflexive_class"].is_number() {
            assert!(frame.observed_reflexive().is_some());
        }
    }
}

#[test]
fn budget_boundary_control_exercises_every_frozen_limit() {
    let corpus = corpus();
    let control = corpus["positive_controls"]
        .as_array()
        .expect("controls")
        .iter()
        .find(|control| control["id"] == "rz_peer_budget_boundary_valid")
        .expect("budget boundary control");
    let bytes = vector_bytes(control);
    let frame = codec::decode(&bytes).expect("boundary vector must decode");
    assert_eq!(frame.kind(), 2, "budget boundary control is a Peer frame");
    assert_eq!(frame.candidates().len(), MAX_CANDIDATES_PER_FRAME);
    assert_eq!(bytes.len(), 2_463);
    assert!(bytes.len() < MAX_FRAME_BYTES);

    let relay_offers = frame
        .candidates()
        .iter()
        .filter_map(|candidate| match candidate {
            Candidate::Relay(relay) => Some(relay.signed_offer().len()),
            Candidate::Lan(_) | Candidate::Reflexive(_) | Candidate::Other(_) => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(relay_offers.len(), MAX_RELAY_CANDIDATES_PER_FRAME);
    assert_eq!(
        relay_offers,
        vec![MAX_SIGNED_OFFER_BYTES, MAX_SIGNED_OFFER_BYTES]
    );
}

#[test]
fn every_codec_error_vector_maps_to_its_exact_error() {
    let corpus = corpus();
    let vectors = corpus["codec_error_vectors"]
        .as_array()
        .expect("codec vectors");
    assert_eq!(vectors.len(), 11);

    let mut seen = Vec::new();
    for (index, vector) in vectors.iter().enumerate() {
        assert_eq!(
            vector["precedence_step"].as_u64(),
            Some(u64::try_from(index + 1).expect("small index"))
        );
        let bytes = vector_bytes(vector);
        let error = codec::decode(&bytes).expect_err("negative KAT must fail");
        let expected = vector["expected_local_error"]
            .as_str()
            .expect("expected_local_error");
        assert_eq!(error.id(), expected, "{}", vector["id"]);
        seen.push(error.id());
    }
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 11, "the eleven codec errors remain distinct");
}

#[test]
fn duplicate_canonical_class_key_witness_is_wrong_shape_before_dispatch() {
    let corpus = corpus();
    let witnesses = corpus["codec_shape_witnesses"]
        .as_array()
        .expect("codec shape witnesses");
    assert_eq!(witnesses.len(), 1);
    let witness = &witnesses[0];
    assert_eq!(witness["id"], "duplicate_canonical_class_key");
    assert_eq!(witness["precedence_step"], 8);
    assert_eq!(witness["class_agnostic_pre_dispatch"], true);

    let bytes = vector_bytes(witness);
    let decoded: CborValue =
        cbor::from_canonical_slice(&bytes).expect("ordered duplicate witness is well-formed CBOR");
    assert_eq!(
        cbor::to_canonical_vec(&decoded).expect("witness re-encodes"),
        bytes,
        "ordered duplicate is canonical and must not be classified as #4"
    );
    assert_eq!(codec::decode(&bytes), Err(CodecError::WrongShape));
    assert_eq!(witness["expected_local_error"], CodecError::WrongShape.id());
}

#[test]
fn wrong_domain_precedes_duplicate_key_shape_rejection() {
    let bytes = canonical_duplicate_key_frame("wrong.owner-mesh.domain", codec::VERSION, 1);
    assert_eq!(codec::decode(&bytes), Err(CodecError::WrongDomain));
}

#[test]
fn unsupported_version_precedes_duplicate_key_shape_rejection() {
    let bytes = canonical_duplicate_key_frame(codec::DOMAIN, codec::VERSION + 1, 1);
    assert_eq!(codec::decode(&bytes), Err(CodecError::VersionUnsupported));
}

#[test]
fn unknown_kind_precedes_duplicate_key_shape_rejection() {
    let bytes = canonical_duplicate_key_frame(codec::DOMAIN, codec::VERSION, 99);
    assert_eq!(codec::decode(&bytes), Err(CodecError::UnknownFrame));
}

#[test]
fn unknown_candidate_class_is_opaque_and_round_trips_byte_exact() {
    let non_bstr_offer = CborValue::Map(vec![
        text_pair("class", integer(7)),
        text_pair(
            "signed_offer",
            CborValue::Text("not-a-byte-string-and-not-schema-in-r1a".to_owned()),
        ),
        text_pair("future_payload", CborValue::Bool(true)),
    ]);
    let oversized_offer = CborValue::Map(vec![
        text_pair("class", integer(8)),
        text_pair(
            "signed_offer",
            CborValue::Bytes(vec![0x5a; MAX_SIGNED_OFFER_BYTES + 1]),
        ),
    ]);
    let expected = [
        (
            7,
            cbor::to_canonical_vec(&non_bstr_offer).expect("candidate encodes"),
        ),
        (
            8,
            cbor::to_canonical_vec(&oversized_offer).expect("candidate encodes"),
        ),
    ];
    let frame_value = CborValue::Map(vec![
        text_pair("kind", integer(1)),
        text_pair("domain", CborValue::Text(codec::DOMAIN.to_owned())),
        text_pair("version", integer(codec::VERSION)),
        text_pair(
            "candidates",
            CborValue::Array(vec![non_bstr_offer, oversized_offer]),
        ),
        text_pair("rendezvous_id", CborValue::Bytes((0_u8..16).collect())),
    ]);
    let bytes = cbor::to_canonical_vec(&frame_value).expect("unknown-class frame encodes");
    let frame = codec::decode(&bytes).expect("unknown class is byte-valid and deferred");
    assert_eq!(frame.candidates().len(), expected.len());
    for (candidate, (expected_class, expected_raw)) in frame.candidates().iter().zip(expected) {
        let Candidate::Other(other) = candidate else {
            panic!("unknown class must decode as opaque Other");
        };
        assert_eq!(other.class(), expected_class);
        assert_eq!(other.raw(), expected_raw.as_slice());
    }
    assert_eq!(codec::encode(&frame), bytes);
}

#[test]
fn every_constructible_multi_violation_obeys_frozen_precedence() {
    let corpus = corpus();
    let vectors = corpus["precedence"]["multi_violation_vectors"]
        .as_array()
        .expect("precedence vectors");
    assert_eq!(vectors.len(), 7);

    for vector in vectors {
        let bytes = vector_bytes(vector);
        let error = codec::decode(&bytes).expect_err("multi-violation KAT must fail");
        assert_eq!(
            error.id(),
            vector["expected_first_error"]
                .as_str()
                .expect("expected_first_error"),
            "{}",
            vector["id"]
        );
    }
}

#[test]
fn relay_subcap_is_enforced_at_the_parse_border() {
    let relay = |last_octet: u8| {
        CborValue::Map(vec![
            text_pair("class", integer(2)),
            text_pair("signed_offer", CborValue::Bytes(vec![last_octet; 16])),
            text_pair(
                "relay_endpoint",
                CborValue::Map(vec![
                    text_pair("ip", CborValue::Bytes(vec![192, 0, 2, last_octet])),
                    text_pair("port", integer(443)),
                ]),
            ),
        ])
    };
    let frame = CborValue::Map(vec![
        text_pair("kind", integer(1)),
        text_pair("domain", CborValue::Text(codec::DOMAIN.to_owned())),
        text_pair("version", integer(codec::VERSION)),
        text_pair(
            "candidates",
            CborValue::Array(vec![relay(1), relay(2), relay(3)]),
        ),
        text_pair("rendezvous_id", CborValue::Bytes((0_u8..16).collect())),
    ]);
    let bytes = cbor::to_canonical_vec(&frame).expect("test frame encodes");
    assert_eq!(codec::decode(&bytes), Err(CodecError::FrameTooLarge));
}

#[test]
fn signed_offer_is_opaque_and_never_signature_parsed() {
    let corpus = corpus();
    for id in [
        "rz_hello_valid",
        "rz_peer_valid",
        "rz_peer_budget_boundary_valid",
    ] {
        let control = corpus["positive_controls"]
            .as_array()
            .expect("controls")
            .iter()
            .find(|control| control["id"] == id)
            .expect("opaque-offer control");
        let bytes = vector_bytes(control);
        let frame = codec::decode(&bytes).expect("synthetic opaque offers must decode");
        assert_eq!(codec::encode(&frame), bytes);
    }
}

#[test]
fn behavioral_and_cross_layer_errors_are_declared_but_not_claimed_by_codec() {
    let corpus = corpus();
    assert_eq!(
        corpus["behavioral_only"]["declared_without_byte_vectors"]
            .as_array()
            .expect("behavioral declarations")
            .len(),
        7
    );
    assert_eq!(
        corpus["behavioral_only"]["excluded_cross_layer"]["id"],
        "err.a2_handshake_failed"
    );
    assert_eq!(corpus["taxonomy_counts"]["section_7_2_total"], 8);
}

#[test]
fn r1a7_enumerates_linked_targets_and_proves_zero_production_callers() {
    let root = repository_root();
    let rust_root = root.join("admin/rust");
    let members = workspace_members(&rust_root);
    // 28 + 1 `tunnel-wire-rs` (S0) + 1 `device-key-rs` (S1). Derived, not
    // bumped: the neutral wire crate is the mechanism for the S0 cross-import
    // boundary — with no dependency edge to `household-rs`, no `pub use` chain
    // there can make claw authority resolve from neutral code, which a grep
    // over source text cannot enforce. `device-key-rs` is the S1 device-static
    // crate: it enters with NO production caller (the S1 slice is the type,
    // the keystore round-trip and its guards; the FFI stayed out per design
    // §5.3), and its own guard forbids the `household-rs` edge so the R1a
    // codec cannot become reachable through it.
    // Note the asymmetry with `targets` below: `parse_member_manifest` reads
    // explicit targets only from `[[bin]]`/`[[test]]`/`[[example]]`, so these
    // crates' single-bracket `[lib]` is invisible to it, and tunnel-wire-rs
    // ships its tests as inline `mod tests` rather than files under `tests/`.
    // device-key-rs DOES ship files under `tests/` (device_static,
    // s1_design_guards), so members moves by one and targets moves by two.
    //
    // +1 `mesh-session-runtime-rs` (D6 runtime facade). Derived, not bumped: it
    // joins as a REAL member rather than staying standalone, because a crate
    // outside the workspace is not built by `--workspace` and therefore has no
    // CI at all. It declares no `[[bin]]`/`[[test]]`/`[[example]]` and ships no
    // `src/main.rs`, `src/bin/`, `tests/` or `examples/`, so by
    // `enumerate_workspace_targets`'s own rule it contributes ZERO targets --
    // members moves by one and targets does not move for it.
    assert_eq!(members.len(), 31, "workspace member inventory changed");
    assert!(
        members
            .iter()
            .any(|member| member == "m1-household-mesh-smoke-rs")
    );
    let targets = enumerate_workspace_targets(&rust_root, &members);
    // 201 + 5. DERIVED FROM MEASUREMENT, then explained -- not summed. The
    // composition adds seven files under `tests/`, of which exactly five are
    // enumerated targets:
    //
    //   household-rs/tests/compile_fail_peer_expectation.rs      (lifecycle)
    //   household-rs/tests/compile_fail_pending_admission.rs     (integration)
    //   household-rs/tests/compile_fail_fixture_coverage.rs      (orphan gate)
    //   household-rs/tests/workspace_msrv_invariant.rs           (MSRV floor)
    //   server-rs/tests/khai_b3_exposure_decision_guard.rs       (B-3 exposure)
    //
    // The other two, `mesh-session-control-model-rs/tests/{cas_multiprocess,
    // model_invariants}.rs`, do NOT count: that crate is in the workspace's
    // `exclude` list, so it is not a member and `enumerate_workspace_targets`
    // never walks it. `mesh-session-runtime-rs` joins as a member but declares
    // no explicit targets and ships no `tests/`, so it adds zero here.
    //
    // Every arithmetic prediction of this number made during composition was
    // wrong (206, then 207, by two different routes). The value below is what
    // the enumerator reported; the list above is why.
    assert_eq!(targets.len(), 206, "Cargo target inventory changed");
    assert_eq!(
        targets.iter().filter(|target| target.kind == "bin").count(),
        50
    );
    assert_eq!(
        targets
            .iter()
            .filter(|target| target.kind == "test")
            .count(),
        156 // 146 + 2 R0a Fatia N + 1 B0a roster-currency + 2 device-key-rs S1 integration targets + 5 mesh-session composition targets
    );
    assert_eq!(
        targets
            .iter()
            .filter(|target| target.kind == "example")
            .count(),
        0
    );
    assert!(targets.iter().any(|target| {
        target.package == "server-rs" && target.kind == "bin" && target.name == "server"
    }));
    assert!(targets.iter().any(|target| {
        target.package == "server-rs"
            && target.kind == "bin"
            && target.name == "server-rs"
            && target.path == "server-rs/src/main.rs"
    }));
    assert!(targets.iter().any(|target| {
        target.package == "server-rs"
            && target.kind == "test"
            && target.name == "m2a_shared_claw_control_plane_contract"
            && target.path == "server-rs/tests/m2a_shared_claw_control_plane_contract.rs"
    }));
    assert!(targets.iter().any(|target| {
        target.package == "m1-household-mesh-smoke-rs"
            && target.kind == "bin"
            && target.name == "m1-household-mesh-smoke"
            && target.path == "m1-household-mesh-smoke-rs/src/main.rs"
    }));
    assert!(targets.iter().any(|target| {
        target.package == "m1-household-mesh-smoke-rs"
            && target.kind == "test"
            && target.name == "workspace_boundary"
            && target.path == "m1-household-mesh-smoke-rs/tests/workspace_boundary.rs"
    }));
    assert!(targets.iter().any(|target| {
        target.package == "household-rs"
            && target.kind == "test"
            && target.name == "caveat_narrowing"
            && target.path == "household-rs/tests/caveat_narrowing.rs"
    }));
    assert!(targets.iter().any(|target| {
        target.package == "household-rs"
            && target.kind == "test"
            && target.name == "r0a_implementation_scope_guard"
            && target.path == "household-rs/tests/r0a_implementation_scope_guard.rs"
    }));

    eprintln!("R1a.7 workspace crates ({}):", members.len());
    for member in &members {
        eprintln!("  {member}");
    }
    eprintln!("R1a.7 Cargo targets ({}):", targets.len());
    for target in &targets {
        eprintln!(
            "  {}/{} [{}] {}",
            target.package, target.name, target.kind, target.path
        );
    }

    let codec_path = rust_root.join("household-rs/src/owner_mesh_rendezvous_codec.rs");
    let lib_path = rust_root.join("household-rs/src/lib.rs");
    let r1a_test_path = rust_root.join("household-rs/tests/owner_mesh_rendezvous_codec.rs");
    let mut workspace_sources = Vec::new();
    collect_workspace_rust_sources(&rust_root, &mut workspace_sources);
    workspace_sources.sort();

    let canonical_workspace_sources = workspace_sources
        .iter()
        .map(|path| fs::canonicalize(path).expect("canonicalize workspace Rust source"))
        .collect::<BTreeSet<_>>();
    for target in &targets {
        let target_path = fs::canonicalize(rust_root.join(&target.path))
            .unwrap_or_else(|error| panic!("canonicalize Cargo target {}: {error}", target.path));
        assert!(
            canonical_workspace_sources.contains(&target_path),
            "Cargo target escapes the workspace-wide R1a.7 source scan: {}/{} [{}] {}",
            target.package,
            target.name,
            target.kind,
            target.path
        );
    }

    for path in workspace_sources {
        if path == codec_path {
            continue;
        }
        let source = fs::read_to_string(&path).expect("read production Rust source");
        if path == lib_path {
            assert_eq!(source.matches("owner_mesh_rendezvous_codec").count(), 1);
            assert!(source.contains("pub mod owner_mesh_rendezvous_codec;"));
            assert!(
                !source.contains("pub use owner_mesh_rendezvous_codec")
                    && !source.contains("pub use crate::owner_mesh_rendezvous_codec")
                    && !source.contains("owner_mesh_rendezvous_codec::*"),
                "household-rs lib root must not re-export codec items or glob"
            );
        } else if path == r1a_test_path {
            assert!(
                source.contains("household_rs::owner_mesh_rendezvous_codec"),
                "R1a integration test must exercise the public codec path"
            );
        } else {
            assert!(
                !source.contains("owner_mesh_rendezvous_codec"),
                "workspace caller or import reaches R1a codec outside its own test: {}",
                path.display()
            );
        }
    }
}

#[test]
fn module_is_pure_product_a_isolated_and_literal_marker_clean() {
    let root = repository_root();
    let module_path = root.join("admin/rust/household-rs/src/owner_mesh_rendezvous_codec.rs");
    let source = fs::read_to_string(module_path).expect("read codec source");

    for forbidden in [
        "std::net",
        "tokio::",
        "async fn",
        "TcpStream",
        "UdpSocket",
        "MachineCert",
        "owner_auth::",
        "claw_share",
        "p256::",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden R1a symbol: {forbidden}"
        );
    }

    let markers = fs::read_to_string(root.join("admin/rust/phase0-forbidden-markers.txt"))
        .expect("read literal Phase-0 markers");
    let markers = markers
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();
    assert_eq!(markers.len(), 18, "marker proof must remain non-vacuous");
    for marker in markers {
        assert!(
            !source.contains(marker),
            "literal Phase-0 marker entered inert codec: {marker}"
        );
    }
}

#[test]
fn parse_borders_cap_retention_without_inverting_error_precedence() {
    let module_path =
        repository_root().join("admin/rust/household-rs/src/owner_mesh_rendezvous_codec.rs");
    let source = fs::read_to_string(module_path).expect("read codec source");

    assert!(source.contains("Vec::with_capacity(values.len().min(MAX_CANDIDATES_PER_FRAME))"));
    assert!(source.contains("let retain = candidates.len() < MAX_CANDIDATES_PER_FRAME"));
    assert!(source.contains("let parsed = parse_candidate(value, retain)?"));
    assert!(source.contains("if let Some(candidate) = parsed.value"));
    assert!(source.contains("let value = endpoint.map(|endpoint|"));
    assert!(source.contains("if retain {\n        Ok(Some(Endpoint"));
    assert!(source.contains("} else {\n        Ok(None)"));
    let offer_measure = source
        .find("let signed_offer_too_large = signed_offer.len() >")
        .expect("signed-offer length is measured at the parse border");
    let offer_empty = source[offer_measure..]
        .find("Vec::new()")
        .map(|offset| offer_measure + offset)
        .expect("oversized offer is represented without copying its bytes");
    let offer_copy = source[offer_empty..]
        .find("signed_offer.to_vec()")
        .map(|offset| offer_empty + offset)
        .expect("in-budget offer copy remains available");
    assert!(offer_measure < offer_empty && offer_empty < offer_copy);

    let unknown = source
        .find("if parsed.has_unknown_field")
        .expect("unknown-field precedence check");
    let count = source
        .find("if parsed.candidate_count > MAX_CANDIDATES_PER_FRAME")
        .expect("candidate-count precedence check");
    let offer = source
        .find("if parsed.signed_offer_too_large")
        .expect("offer-size precedence check");
    assert!(unknown < count && count < offer);
}

fn text_pair(key: &str, value: CborValue) -> (CborValue, CborValue) {
    (CborValue::Text(key.to_owned()), value)
}

fn integer(value: u64) -> CborValue {
    CborValue::Integer(value.into())
}

fn canonical_duplicate_key_frame(domain: &str, version: u64, kind: u64) -> Vec<u8> {
    let rendezvous_id = CborValue::Bytes((0_u8..16).collect());
    let frame = CborValue::Map(vec![
        text_pair("kind", integer(kind)),
        text_pair("domain", CborValue::Text(domain.to_owned())),
        text_pair("version", integer(version)),
        text_pair("candidates", CborValue::Array(Vec::new())),
        text_pair("rendezvous_id", rendezvous_id.clone()),
        text_pair("rendezvous_id", rendezvous_id),
    ]);
    let bytes = cbor::to_canonical_vec(&frame).expect("synthetic duplicate-key frame encodes");
    assert!(bytes.len() < MAX_FRAME_BYTES);
    let decoded: CborValue =
        cbor::from_canonical_slice(&bytes).expect("synthetic duplicate-key frame decodes");
    assert_eq!(
        cbor::to_canonical_vec(&decoded).expect("synthetic frame re-encodes"),
        bytes,
        "synthetic duplicate-key frame remains canonical"
    );
    bytes
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CargoTarget {
    package: String,
    kind: String,
    name: String,
    path: String,
}

struct ExplicitTarget {
    kind: String,
    name: String,
    path: Option<String>,
}

struct TargetDraft {
    kind: String,
    name: Option<String>,
    path: Option<String>,
}

struct MemberManifest {
    package: String,
    autobins: bool,
    autotests: bool,
    autoexamples: bool,
    explicit_targets: Vec<ExplicitTarget>,
}

fn workspace_members(rust_root: &Path) -> Vec<String> {
    let manifest =
        fs::read_to_string(rust_root.join("Cargo.toml")).expect("read workspace Cargo.toml");
    let (_, after_start) = manifest
        .split_once("members = [")
        .expect("workspace members array");
    let (members_block, _) = after_start
        .split_once(']')
        .expect("workspace members closing bracket");
    let members = members_block
        .lines()
        .filter_map(|line| {
            let value = line
                .split('#')
                .next()
                .expect("split always yields one item")
                .trim()
                .trim_end_matches(',')
                .trim();
            if value.is_empty() {
                return None;
            }
            assert!(
                value.starts_with('"') && value.ends_with('"'),
                "unsupported workspace member syntax: {value}"
            );
            Some(value[1..value.len() - 1].to_owned())
        })
        .collect::<Vec<_>>();
    assert!(
        members.iter().all(|member| !member.contains('*')),
        "workspace glob members require explicit R1a.7 support"
    );
    members
}

fn enumerate_workspace_targets(rust_root: &Path, members: &[String]) -> BTreeSet<CargoTarget> {
    let mut targets = BTreeSet::new();
    for member in members {
        let package_dir = rust_root.join(member);
        let manifest = parse_member_manifest(&package_dir);

        for target in manifest.explicit_targets {
            let path = target.path.map_or_else(
                || {
                    infer_explicit_target_path(
                        &package_dir,
                        &target.kind,
                        &target.name,
                        &manifest.package,
                    )
                },
                |path| package_dir.join(path),
            );
            assert!(
                path.is_file(),
                "explicit Cargo target path does not exist: {}",
                path.display()
            );
            insert_target(
                &mut targets,
                rust_root,
                &manifest.package,
                &target.kind,
                &target.name,
                &path,
            );
        }

        if manifest.autobins {
            let main = package_dir.join("src/main.rs");
            if main.is_file() {
                insert_target(
                    &mut targets,
                    rust_root,
                    &manifest.package,
                    "bin",
                    &manifest.package,
                    &main,
                );
            }
            discover_directory_targets(
                &mut targets,
                rust_root,
                &manifest.package,
                "bin",
                &package_dir.join("src/bin"),
            );
        }
        if manifest.autotests {
            discover_directory_targets(
                &mut targets,
                rust_root,
                &manifest.package,
                "test",
                &package_dir.join("tests"),
            );
        }
        if manifest.autoexamples {
            discover_directory_targets(
                &mut targets,
                rust_root,
                &manifest.package,
                "example",
                &package_dir.join("examples"),
            );
        }
    }
    targets
}

fn parse_member_manifest(package_dir: &Path) -> MemberManifest {
    let manifest_path = package_dir.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", manifest_path.display()));
    let mut section = "";
    let mut package = None;
    let mut autobins = true;
    let mut autotests = true;
    let mut autoexamples = true;
    let mut explicit_targets = Vec::new();
    let mut target_draft = None;

    for raw_line in manifest.lines() {
        let line = raw_line
            .split('#')
            .next()
            .expect("split always yields one item")
            .trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("[[") {
            finish_target_draft(&mut target_draft, &mut explicit_targets);
            target_draft = match line {
                "[[bin]]" => Some(TargetDraft {
                    kind: "bin".to_owned(),
                    name: None,
                    path: None,
                }),
                "[[test]]" => Some(TargetDraft {
                    kind: "test".to_owned(),
                    name: None,
                    path: None,
                }),
                "[[example]]" => Some(TargetDraft {
                    kind: "example".to_owned(),
                    name: None,
                    path: None,
                }),
                _ => None,
            };
            section = "";
            continue;
        }
        if line.starts_with('[') {
            finish_target_draft(&mut target_draft, &mut explicit_targets);
            section = if line == "[package]" { "package" } else { "" };
            continue;
        }

        if let Some(target) = target_draft.as_mut() {
            if let Some(value) = toml_string_value(line, "name") {
                target.name = Some(value);
            } else if let Some(value) = toml_string_value(line, "path") {
                target.path = Some(value);
            }
            continue;
        }

        if section == "package" {
            if let Some(value) = toml_string_value(line, "name") {
                package = Some(value);
            } else if let Some(value) = toml_bool_value(line, "autobins") {
                autobins = value;
            } else if let Some(value) = toml_bool_value(line, "autotests") {
                autotests = value;
            } else if let Some(value) = toml_bool_value(line, "autoexamples") {
                autoexamples = value;
            }
        }
    }
    finish_target_draft(&mut target_draft, &mut explicit_targets);

    MemberManifest {
        package: package
            .unwrap_or_else(|| panic!("package name missing in {}", manifest_path.display())),
        autobins,
        autotests,
        autoexamples,
        explicit_targets,
    }
}

fn finish_target_draft(draft: &mut Option<TargetDraft>, targets: &mut Vec<ExplicitTarget>) {
    let Some(draft) = draft.take() else {
        return;
    };
    targets.push(ExplicitTarget {
        kind: draft.kind,
        name: draft.name.expect("explicit Cargo target name"),
        path: draft.path,
    });
}

fn toml_string_value(line: &str, key: &str) -> Option<String> {
    let (left, right) = line.split_once('=')?;
    if left.trim() != key {
        return None;
    }
    let value = right.trim();
    assert!(
        value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\''))),
        "unsupported TOML string for {key}: {value}"
    );
    Some(value[1..value.len() - 1].to_owned())
}

fn toml_bool_value(line: &str, key: &str) -> Option<bool> {
    let (left, right) = line.split_once('=')?;
    if left.trim() != key {
        return None;
    }
    match right.trim() {
        "true" => Some(true),
        "false" => Some(false),
        value => panic!("unsupported TOML bool for {key}: {value}"),
    }
}

fn infer_explicit_target_path(
    package_dir: &Path,
    kind: &str,
    name: &str,
    package: &str,
) -> PathBuf {
    let mut candidates = match kind {
        "bin" => vec![
            package_dir.join(format!("src/bin/{name}.rs")),
            package_dir.join(format!("src/bin/{name}/main.rs")),
        ],
        "test" => vec![
            package_dir.join(format!("tests/{name}.rs")),
            package_dir.join(format!("tests/{name}/main.rs")),
        ],
        "example" => vec![
            package_dir.join(format!("examples/{name}.rs")),
            package_dir.join(format!("examples/{name}/main.rs")),
        ],
        _ => panic!("unsupported Cargo target kind: {kind}"),
    };
    if kind == "bin" && name == package {
        candidates.push(package_dir.join("src/main.rs"));
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("cannot infer path for explicit {kind} target {name}"))
}

fn discover_directory_targets(
    targets: &mut BTreeSet<CargoTarget>,
    rust_root: &Path,
    package: &str,
    kind: &str,
    directory: &Path,
) {
    if !directory.is_dir() {
        return;
    }
    let mut entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        .map(|entry| entry.expect("read target directory entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_file() && path.extension().and_then(|extension| extension.to_str()) == Some("rs")
        {
            let name = path
                .file_stem()
                .and_then(|name| name.to_str())
                .expect("UTF-8 target name");
            insert_target(targets, rust_root, package, kind, name, &path);
        } else if path.is_dir() {
            let main = path.join("main.rs");
            if main.is_file() {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("UTF-8 target directory name");
                insert_target(targets, rust_root, package, kind, name, &main);
            }
        }
    }
}

fn insert_target(
    targets: &mut BTreeSet<CargoTarget>,
    rust_root: &Path,
    package: &str,
    kind: &str,
    name: &str,
    path: &Path,
) {
    let path = path
        .strip_prefix(rust_root)
        .expect("target remains inside Rust workspace")
        .to_string_lossy()
        .replace('\\', "/");
    targets.insert(CargoTarget {
        package: package.to_owned(),
        kind: kind.to_owned(),
        name: name.to_owned(),
        path,
    });
}

fn collect_workspace_rust_sources(directory: &Path, output: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("read Rust workspace directory") {
        let entry = entry.expect("read directory entry");
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|name| name.to_str());
            if matches!(name, Some("target" | ".git")) {
                continue;
            }
            collect_workspace_rust_sources(&path, output);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            output.push(path);
        }
    }
}

#[test]
fn public_constructors_reject_invalid_shapes_without_state_or_io() {
    assert_eq!(IpBytes::new(vec![0; 5]), Err(CodecError::WrongShape));
    let ip = IpBytes::new(vec![192, 0, 2, 1]).expect("valid IPv4 bytes");
    assert_eq!(Endpoint::new(ip, 0), Err(CodecError::WrongShape));

    let endpoint = Endpoint::new(
        IpBytes::new(vec![192, 0, 2, 1]).expect("valid IPv4 bytes"),
        443,
    )
    .expect("valid endpoint");
    assert_eq!(
        household_rs::owner_mesh_rendezvous_codec::RelayCandidate::new(
            endpoint,
            vec![0; MAX_SIGNED_OFFER_BYTES + 1]
        ),
        Err(CodecError::SignedOfferTooLarge)
    );

    let endpoint = || {
        Endpoint::new(
            IpBytes::new(vec![192, 0, 2, 1]).expect("valid IPv4 bytes"),
            443,
        )
        .expect("valid endpoint")
    };
    let candidates = (0..=MAX_CANDIDATES_PER_FRAME)
        .map(|_| Candidate::Lan(endpoint()))
        .collect();
    assert_eq!(
        Frame::hello(
            codec::RendezvousId::new([0; RENDEZVOUS_ID_BYTES]),
            candidates
        ),
        Err(CodecError::FrameTooLarge)
    );
}

/// True if this manifest inherits the workspace lint table, in EITHER spelling.
///
/// Both forms are accepted deliberately. Cargo treats
///
/// ```toml
/// [lints]
/// workspace = true
/// ```
///
/// and the dotted `lints.workspace = true` as the same thing, and every member
/// here happens to use the table form. A checker that recognised only the
/// dotted spelling would report zero of thirty members opting in and conclude
/// the workspace lint table was inert — which is exactly the wrong conclusion,
/// reached exactly that way, before this guard existed. Matching one spelling
/// is how a search fails toward "nobody is protected".
fn declares_workspace_lint_inheritance(manifest: &str) -> bool {
    let code = |line: &str| {
        line.split('#')
            .next()
            .unwrap_or("")
            .replace(char::is_whitespace, "")
    };
    if manifest.lines().any(|l| code(l) == "lints.workspace=true") {
        return true;
    }
    let mut in_lints = false;
    for line in manifest.lines() {
        let stripped = code(&line);
        if stripped.starts_with('[') {
            in_lints = stripped == "[lints]";
            continue;
        }
        if in_lints && stripped == "workspace=true" {
            return true;
        }
    }
    false
}

/// Every workspace member must inherit `[workspace.lints]`.
///
/// The line is load-bearing and its absence is SILENT. Drop it from a member and
/// the real gate — `cargo clippy --workspace -- -D warnings` — stops applying
/// `clippy::all` and `pedantic` to that crate entirely, while still exiting 0.
/// The crate simply stops being linted, and no existing check notices: the only
/// other mention of `[lints]` in test code uses the string as a delimiter for
/// slicing a `[dependencies]` section, not as a property to enforce.
///
/// So the thirty members that do inherit are correct by convention, not by
/// mechanism — a thirty-first joins unlinted and nothing fails. That is worse
/// than the target ratchet, which at least shouts when its number moves.
#[test]
fn every_workspace_member_inherits_the_workspace_lint_table() {
    let rust_root = repository_root().join("admin/rust");
    let members = workspace_members(&rust_root);

    // Positive control: a broken enumerator returning an empty list would make
    // the emptiness check below pass while examining nothing.
    assert!(
        members.len() >= 25,
        "only {} workspace members enumerated; the member parse is broken, so \
         this guard would pass without checking anything",
        members.len()
    );

    let missing: Vec<&String> = members
        .iter()
        .filter(|member| {
            let manifest = fs::read_to_string(rust_root.join(member).join("Cargo.toml"))
                .unwrap_or_else(|error| panic!("read {member}/Cargo.toml: {error}"));
            !declares_workspace_lint_inheritance(&manifest)
        })
        .collect();

    assert!(
        missing.is_empty(),
        "workspace members that do NOT inherit `[workspace.lints]`: {missing:?}. \
         Without it the member is silently exempt from `clippy::all` and \
         `pedantic` under the real gate, which still exits 0 — the crate stops \
         being linted and nothing else notices. Add `[lints]` with \
         `workspace = true` to each."
    );
}

/// Unit coverage for [`declares_workspace_lint_inheritance`] itself.
///
/// The workspace-wide test above can only exercise the shapes that happen to be
/// in the tree — today that is thirty identical table-form declarations, so it
/// proves the recogniser works for exactly one case. @khai's independent
/// verification of the guard supplied two more shapes by mutating a real
/// manifest and running the gate. That kind of check evaporates when the
/// transcript scrolls away, so it is restated here as a standing assertion:
/// each accepted and each rejected shape gets its own case, because a
/// recogniser claiming to handle several forms and only ever exercised on one
/// looks identical and has a fraction of the coverage.
#[test]
fn lint_inheritance_recogniser_accepts_and_rejects_the_right_shapes() {
    // Accepted: the two spellings cargo treats as equivalent.
    assert!(declares_workspace_lint_inheritance(
        "[package]\nname = \"x\"\n\n[lints]\nworkspace = true\n"
    ));
    assert!(declares_workspace_lint_inheritance(
        "lints.workspace = true\n[package]\nname = \"x\"\n"
    ));
    assert!(
        declares_workspace_lint_inheritance("[lints]\nworkspace   =   true\n"),
        "whitespace around the value must not change the meaning"
    );

    // Rejected: present but explicitly NOT inheriting. This is the shape a
    // recogniser that merely looked for the `[lints]` section would wave
    // through, and it is the one that matters -- the member opts OUT on
    // purpose and would be silently unlinted.
    assert!(!declares_workspace_lint_inheritance(
        "[package]\nname = \"x\"\n\n[lints]\nworkspace = false\n"
    ));

    // Rejected: a member declaring its OWN lint table instead of inheriting.
    // `[lints.clippy]` is a different section from `[lints]`, and the workspace
    // table does not reach it.
    assert!(!declares_workspace_lint_inheritance(
        "[package]\nname = \"x\"\n\n[lints.clippy]\nall = \"warn\"\n"
    ));

    // Rejected: absent entirely, and absent-after-another-section, which is
    // where a section-scanner that forgets to reset its state goes wrong.
    assert!(!declares_workspace_lint_inheritance(
        "[package]\nname = \"x\"\n"
    ));
    assert!(!declares_workspace_lint_inheritance(
        "[lints]\nworkspace = true\n[dependencies]\nserde = \"1\"\n[other]\nworkspace = true\n"
            .replace("[lints]\nworkspace = true\n", "")
            .as_str()
    ));

    // Rejected: commented out. A guard that counts commented declarations
    // reports protection that is not there.
    assert!(!declares_workspace_lint_inheritance(
        "[lints]\n# workspace = true\n"
    ));
}

/// A silencing `allow` must keep its receipt.
///
/// `[workspace.lints.clippy]` carries two entries that suppress real findings —
/// `collapsible_if` and `manual_is_multiple_of` — allowed rather than fixed
/// because the fixes are ~180 mechanical edits across 15 crates that would
/// collide with branches held mid-composition. That trade is defensible only
/// while the reasoning travels with it. Delete the explanation and what remains
/// is indistinguishable from policy: two lints nobody enforces, for reasons
/// nobody can reconstruct.
///
/// Scope, stated honestly because it is narrower than it looks: this guards the
/// RECEIPT, not the repayment. It cannot make the post-composition sweep happen,
/// and it does not stop the suppressed count from growing — an `allow` silences
/// the gate, so new violations land free. The stronger instrument is a count
/// ratchet (tolerate today's N, fail at N+1), which needs a second
/// whole-workspace clippy run to measure; that cost is exactly what gets a gate
/// switched off, so it is a composition-time decision rather than something
/// smuggled in here.
#[test]
fn msrv_lint_debt_keeps_its_justification() {
    let manifest = fs::read_to_string(repository_root().join("admin/rust/Cargo.toml"))
        .expect("read workspace Cargo.toml");

    for lint in ["collapsible_if", "manual_is_multiple_of"] {
        let Some(line) = manifest
            .lines()
            .find(|line| line.trim_start().starts_with(lint))
        else {
            // Absent is fine and is the intended end state: the sweep happened
            // and the entry was removed.
            continue;
        };
        assert!(
            line.contains("allow"),
            "`{lint}` is declared at workspace level but not as an allow; if its \
             level changed, this guard's premise changed with it"
        );
        assert!(
            line.contains('#'),
            "the `{lint}` allow lost its inline measurement. The number of sites \
             it suppresses is what makes the trade auditable — without it the \
             entry is an unexplained silence."
        );
    }

    let suppresses_anything = ["collapsible_if", "manual_is_multiple_of"]
        .iter()
        .any(|lint| {
            manifest
                .lines()
                .any(|line| line.trim_start().starts_with(lint))
        });
    if !suppresses_anything {
        return; // debt repaid; nothing left to justify
    }

    for marker in [
        "MSRV-woken lint debt",
        "FOLLOW-UP",
        "DELETE these two lines",
    ] {
        assert!(
            manifest.contains(marker),
            "the MSRV lint-debt receipt lost its `{marker}` section. These allows \
             were accepted as debt with a written reason and an explicit \
             repayment instruction; strip either and the next reader inherits \
             two silenced lints with no way to tell whether that was a decision \
             or an accident."
        );
    }
}
