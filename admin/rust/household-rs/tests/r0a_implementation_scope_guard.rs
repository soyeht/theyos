use std::fs;
use std::path::{Path, PathBuf};

fn package_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_workspace() -> PathBuf {
    package_dir()
        .parent()
        .expect("household-rs is a workspace child")
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
    fs::read_to_string(path).expect("scope-guard source is UTF-8")
}

fn code_only(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Code with comments stripped AND the inline `#[cfg(test)]` module *excised*,
/// keeping the production source on BOTH sides of it.
///
/// Fatia D2a keeps its focused tests inline (see
/// `r0a_d2a_tests_stay_inline_and_off_the_cargo_target_ratchet`), so a marker
/// that is legitimate in a negative test — `HouseholdAddMachine`, for one —
/// would otherwise be indistinguishable from the same marker leaking into
/// production. Boundary bans are asserted against this projection only.
///
/// This function used to truncate at the first `#[cfg(test)]` and return the
/// prefix. That made every ban blind to anything placed *after* `mod tests`, so
/// the cheapest possible escape — appending a banned item at the end of the
/// file — was never scanned. The region is now excised rather than truncated
/// at, which is also what keeps the in-test negative from becoming a false
/// positive: simply scanning the whole file would report it as a leak.
///
/// The test module is delimited structurally. A top-level item closes on the
/// first line that is exactly `}` at column 0 — rustfmt guarantees this, every
/// line nested inside the module is indented, and an indented string literal
/// containing a brace therefore cannot forge the delimiter. That avoids
/// brace-counting, which would be defeated by braces inside string literals
/// (`format!("{name}.tmp")` and friends appear in both scanned modules).
fn production_only(source: &str) -> String {
    let code = code_only(source);
    let lines: Vec<&str> = code.lines().collect();

    let mut kept: Vec<&str> = Vec::with_capacity(lines.len());
    let mut index = 0usize;
    let mut regions = 0usize;
    while index < lines.len() {
        // Only a column-0 attribute delimits a top-level test region; a nested
        // `#[cfg(test)]` is indented and must not open one.
        if lines[index] == "#[cfg(test)]" {
            // Only `mod <name> {` may open an excised region. A non-block item
            // (`#[cfg(test)] struct FailGuard;`) has no column-0 `}` to close
            // on, so scanning ahead for one would swallow production code —
            // fail-open, and exactly the class of hole this guard exists to
            // close. Refuse loudly instead.
            let opener = lines.get(index + 1).copied().unwrap_or("");
            assert!(
                opener.starts_with("mod ") && opener.ends_with(" {"),
                "a top-level #[cfg(test)] must guard `mod <name> {{`, found {opener:?}"
            );
            let end = lines[index + 1..]
                .iter()
                .position(|line| *line == "}")
                .map(|offset| index + 1 + offset)
                .unwrap_or_else(|| panic!("`{opener}` must close on a column-0 brace"));
            index = end + 1;
            regions += 1;
            continue;
        }
        kept.push(lines[index]);
        index += 1;
    }
    assert!(
        regions >= 1,
        "expected at least one top-level #[cfg(test)] module to excise"
    );
    kept.join("\n")
}

/// The body of a `struct Name {` declaration, up to the line that closes it.
///
/// Used to scope field-level assertions to the declaration that actually
/// defines the wire shape, rather than to any mention of the same word
/// elsewhere in the file.
fn struct_block<'a>(source: &'a str, decl: &str) -> &'a str {
    let start = source
        .find(decl)
        .unwrap_or_else(|| panic!("scope guard could not find `{decl}`"));
    let rest = &source[start..];
    let end = rest
        .find("\n}")
        .unwrap_or_else(|| panic!("`{decl}` is unterminated"));
    &rest[..end]
}

#[test]
fn r0a_n_paths_are_limited_and_registered() {
    let lib = read(package_dir().join("src/lib.rs"));
    assert!(lib.contains("pub mod caveat_narrowing;"));
    assert!(lib.contains("pub mod caveats;"));
    assert!(!lib.contains("pub use caveat_narrowing"));
    assert!(!lib.contains("caveat_narrowing::*"));

    // `src/device_cert.rs` used to be listed here. Fatia D2a is the slice that
    // owns it, so its absence is no longer the invariant — its shape is, and
    // that is asserted by the `r0a_d2a_*` tests below. Everything else that was
    // out of scope for N stays out.
    for absent in [
        "src/household_mesh_peer_admission_store.rs",
        "src/owner_mesh_peer_admission.rs",
        "src/live_snapshot.rs",
        "src/owner_mesh_narrowing.rs",
        "src/caveat_narrowing_store.rs",
    ] {
        assert!(
            !package_dir().join(absent).exists(),
            "C/S/A or an alternate N module must stay out of Fatia N: {absent}"
        );
    }
}

#[test]
fn r0a_n_sources_stay_closed_and_effect_free() {
    let caveats = read(package_dir().join("src/caveats.rs"));
    let narrowing = read(package_dir().join("src/caveat_narrowing.rs"));
    let narrowing_code = code_only(&narrowing);
    let production_code = [code_only(&caveats), narrowing_code.clone()].join("\n");

    assert!(caveats.contains("HouseholdAddDevice"));
    assert!(caveats.contains("ConstraintValue"));
    assert!(caveats.contains("pub struct Constraints"));
    assert!(!caveats.contains("ConstraintValue::None"));
    assert!(!caveats.contains("BTreeMap<String, Vec<String>>"));
    assert!(narrowing_code.contains("DeviceCaveatNarrowingProofV1"));
    assert!(narrowing_code.contains("verify_explicit_household_add_device_grant"));
    let proof_offset = narrowing_code
        .find("pub struct DeviceCaveatNarrowingProofV1")
        .expect("opaque proof declaration");
    let preceding_line = narrowing_code[..proof_offset]
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .expect("declaration has preceding source");
    assert!(
        !preceding_line.trim().ends_with(")]"),
        "opaque proof must not carry a derive attribute"
    );
    assert!(!narrowing_code.contains("impl Clone for DeviceCaveatNarrowingProofV1"));
    assert!(!narrowing_code.contains("impl Copy for DeviceCaveatNarrowingProofV1"));
    assert!(!narrowing_code.contains("impl Default for DeviceCaveatNarrowingProofV1"));
    assert!(!narrowing_code.contains("impl Serialize for DeviceCaveatNarrowingProofV1"));
    assert!(!narrowing_code.contains("impl Deserialize for DeviceCaveatNarrowingProofV1"));
    assert!(!narrowing_code.contains("pub fn new("));
    assert!(!narrowing_code.contains("permits("));
    assert!(!narrowing_code.contains("owner_caveats("));
    assert!(!narrowing_code.contains("owner_capability_names("));

    for forbidden in [
        ["Product ", "A"].concat(),
        ["product", "_a"].concat(),
        ["product", "-a"].concat(),
        ["n", "vpn"].concat(),
        ["10.", "44."].concat(),
        ["Claw", "ShareBridge"].concat(),
        ["Ip", "Tunnel"].concat(),
        ["ip", "_tunnel"].concat(),
        ["Relay", "Stream"].concat(),
        ["Claw", "Vpn"].concat(),
        ["Network", "Settings"].concat(),
        ["Mesh", "LogStore"].concat(),
        ["Projected", "State"].concat(),
        ["device", "_cert"].concat(),
        ["owner", "_mesh_admission"].concat(),
        ["household", "_mesh_peer_admission"].concat(),
        ["std", "::net"].concat(),
        ["tokio", "::"].concat(),
        ["Command", "::new"].concat(),
        ["Tcp", "Listener"].concat(),
        ["ure", "q"].concat(),
        ["req", "west"].concat(),
    ] {
        assert!(
            !production_code.contains(&forbidden),
            "Fatia N contains a forbidden effect/boundary marker: {forbidden}"
        );
    }
}

#[test]
fn r0a_n_ratchet_names_new_targets() {
    let ratchet_path = ["owner_mesh_", "rendezvous_codec.rs"].concat();
    let r1a7 = read(package_dir().join("tests").join(ratchet_path));
    for needle in [
        "assert_eq!(targets.len(), 198",
        "filter(|target| target.kind == \"test\")",
        "146 + 2 R0a Fatia N + 1 B0a roster-currency",
        "name == \"caveat_narrowing\"",
        "path == \"household-rs/tests/caveat_narrowing.rs\"",
        "name == \"r0a_implementation_scope_guard\"",
        "path == \"household-rs/tests/r0a_implementation_scope_guard.rs\"",
    ] {
        assert!(r1a7.contains(needle), "R1a.7 is missing `{needle}`");
    }

    let tsv = repository_root()
        .join("admin/contracts/mobile-claw-vpn/v1/owner_present_phase0_artifact_boundary_v1.tsv");
    assert!(
        tsv.is_file(),
        "TSV path must exist and stay byte-intact in Fatia N"
    );
}

// ─── Fatia D2a — device admission authority ─────────────────────────────────

#[test]
fn r0a_d2a_paths_are_limited_and_registered() {
    let lib = read(package_dir().join("src/lib.rs"));
    assert!(lib.contains("pub mod device_cert;"));
    assert!(lib.contains("pub mod device_admission;"));
    // Declared, never re-exported: the crate root must not widen the surface.
    for widening in [
        "pub use device_cert",
        "pub use device_admission",
        "device_cert::*",
        "device_admission::*",
    ] {
        assert!(
            !lib.contains(widening),
            "D2a modules are declared, not re-exported: {widening}"
        );
    }

    for present in ["src/device_cert.rs", "src/device_admission.rs"] {
        assert!(
            package_dir().join(present).is_file(),
            "Fatia D2a owns {present}"
        );
    }

    // Alternate homes and split-out stores stay out of D2a.
    for absent in [
        "src/device_admission_store.rs",
        "src/device_admission_authority.rs",
        "src/household_device_admission.rs",
        "src/directory_devices.rs",
    ] {
        assert!(
            !package_dir().join(absent).exists(),
            "D2a is one authority in one module: {absent}"
        );
    }

    // No server handlers and no second home outside household-rs.
    for absent in [
        "admin/rust/server-rs/src/handlers_device_admission.rs",
        "admin/rust/server-rs/src/device_admission.rs",
    ] {
        assert!(
            !repository_root().join(absent).exists(),
            "D2a installs no production wiring: {absent}"
        );
    }
}

#[test]
fn r0a_d2a_tests_stay_inline_and_off_the_cargo_target_ratchet() {
    // Each `household-rs/tests/*.rs` file is its own Cargo target, and R1a.7
    // pins the workspace target inventory at 198 (149 of them tests) in this
    // composed inventory: the 197/148 D2a was written against plus the one
    // B0a roster-currency integration target. D2a still keeps its focused tests
    // in `#[cfg(test)] mod tests`, so it contributes nothing to that count; a
    // future slice that wants an integration target has to move the ratchet
    // deliberately rather than by accident.
    for absent in [
        "tests/device_cert.rs",
        "tests/device_admission.rs",
        "tests/r0a_d2a_device_admission.rs",
    ] {
        assert!(
            !package_dir().join(absent).exists(),
            "D2a adds no Cargo test target; R1a.7 pins 198/149 and none of it \
             is D2a's: {absent}"
        );
    }

    let ratchet_path = ["owner_mesh_", "rendezvous_codec.rs"].concat();
    let r1a7 = read(package_dir().join("tests").join(ratchet_path));
    assert!(r1a7.contains("assert_eq!(targets.len(), 198"));
    assert!(
        r1a7.contains("149 // 146 + 2 R0a Fatia N + 1 B0a roster-currency integration targets")
    );

    // Coverage ratchet: counts the `#[test]` attribute itself, not any `fn`, so
    // helper functions cannot pad the number. Lower bounds, so a later slice may
    // add tests but not quietly delete them.
    for (module, floor) in [("device_cert.rs", 25), ("device_admission.rs", 54)] {
        let source = read(package_dir().join("src").join(module));
        assert!(
            source.contains("#[cfg(test)]\nmod tests {"),
            "{module} carries its focused tests inline"
        );
        let inline = source
            .lines()
            .filter(|line| line.trim() == "#[test]")
            .count();
        assert!(
            inline >= floor,
            "{module} lost inline coverage: {inline} tests, expected at least {floor}"
        );
    }
}

#[test]
fn r0a_d2a_sealed_fact_is_opaque_and_move_only() {
    let admission = read(package_dir().join("src/device_admission.rs"));
    let code = code_only(&admission);

    for opaque in ["SealedDeviceAdmissionV1", "ConsumedDeviceAdmissionV1"] {
        let decl = format!("pub struct {opaque}");
        let offset = code
            .find(&decl)
            .unwrap_or_else(|| panic!("opaque declaration for {opaque}"));
        let preceding_line = code[..offset]
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .expect("declaration has preceding source");
        assert!(
            !preceding_line.trim().ends_with(")]"),
            "{opaque} must not carry a derive attribute"
        );
        for forbidden in ["Clone", "Copy", "Default", "Serialize", "Deserialize"] {
            assert!(
                !code.contains(&format!("impl {forbidden} for {opaque}")),
                "{opaque} must not implement {forbidden}: an admission must not \
                 be duplicated or turned into a wire format"
            );
        }
        // Redacted Debug — the fact must not print its own bindings.
        assert!(code.contains(&format!("{opaque}(REDACTED)")));
    }

    // Consumed by value, so it cannot be presented twice.
    assert!(code.contains("sealed: SealedDeviceAdmissionV1"));
    // A *public* entry point taking it by reference would let one fact authorize
    // twice. The private recheck helper may borrow it — it authorizes nothing on
    // its own and cannot be reached from outside the module.
    let lines: Vec<&str> = code.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        if !line.contains("sealed: &SealedDeviceAdmissionV1") {
            continue;
        }
        let owner = lines[..index]
            .iter()
            .rev()
            .find(|candidate| candidate.contains("fn "))
            .copied()
            .unwrap_or_default();
        assert!(
            !owner.contains("pub fn "),
            "a public entry point must take the sealed fact by value: {owner}"
        );
    }
    // Produced only by the authority; no public constructor from input.
    assert!(!code.contains("impl SealedDeviceAdmissionV1 {\n    pub fn new("));
    assert!(!code.contains("impl From<") || !code.contains("> for SealedDeviceAdmissionV1"));
}

#[test]
fn r0a_d2a_device_cert_invents_no_validity_window() {
    let cert = read(package_dir().join("src/device_cert.rs"));
    let code = code_only(&cert);
    let wire = struct_block(&code, "pub struct DeviceCert {");

    // Positive controls first: if these fail, the block extraction found the
    // wrong region and every negative below would pass vacuously.
    for present in [
        "pub d_pub: P256PublicKey",
        "pub d_id: DeviceId",
        "pub p_id: PersonId",
        "pub added_at: u64",
        "pub caveats: Option<Vec<Caveat>>",
        "pub signature: P256Signature",
    ] {
        assert!(
            wire.contains(present),
            "DeviceCert v1 field missing: {present}"
        );
    }

    // `MachineCert` v1 has no `not_after` and neither does `DeviceCert` v1. A
    // device's R0a lifetime ends on root/person/generation/revocation change,
    // never on a TTL synthesized in Rust (R0a §6).
    for invented in ["not_before", "not_after", "expires_at", "expires", "ttl"] {
        assert!(
            !wire.contains(invented),
            "DeviceCert v1 must not invent a validity window: {invented}"
        );
    }

    // The narrowing proof is reused from Fatia N, not reimplemented here.
    assert!(code.contains("verify_explicit_household_add_device_grant"));
    assert!(code.contains("DeviceCaveatNarrowingProofV1"));
    assert!(
        !code.contains("fn compare_scope") && !code.contains("fn compare_constraints"),
        "D2a must call the Fatia N verifier, not re-derive the narrowing order"
    );
}

#[test]
fn r0a_d2a_sources_stay_closed_and_effect_free() {
    let cert = read(package_dir().join("src/device_cert.rs"));
    let admission = read(package_dir().join("src/device_admission.rs"));
    let production = [production_only(&cert), production_only(&admission)].join("\n");

    // Positive controls: prove the production projection is non-empty and is
    // the region the bans below are meant to cover.
    for present in [
        "pub struct DeviceCert",
        "pub struct HouseholdDeviceAdmissionAuthorityV1",
        "pub struct SealedDeviceAdmissionV1",
    ] {
        assert!(
            production.contains(present),
            "production projection lost {present}"
        );
    }

    for forbidden in [
        ["Product ", "A"].concat(),
        ["product", "_a"].concat(),
        ["product", "-a"].concat(),
        ["n", "vpn"].concat(),
        ["10.", "44."].concat(),
        ["Claw", "ShareBridge"].concat(),
        ["Ip", "Tunnel"].concat(),
        ["ip", "_tunnel"].concat(),
        ["Relay", "Stream"].concat(),
        ["Claw", "Vpn"].concat(),
        ["Network", "Settings"].concat(),
        ["Mesh", "LogStore"].concat(),
        ["Projected", "State"].concat(),
        ["std", "::net"].concat(),
        ["tokio", "::"].concat(),
        ["Command", "::new"].concat(),
        ["Tcp", "Listener"].concat(),
        ["ure", "q"].concat(),
        ["req", "west"].concat(),
    ] {
        assert!(
            !production.contains(&forbidden),
            "Fatia D2a contains a forbidden effect/boundary marker: {forbidden}"
        );
    }

    // The phone is not a machine (R0a §7): D2a never reads household membership,
    // never touches Shamir, and never mints a machine issuer.
    for forbidden in [
        ["Household", "Record"].concat(),
        ["shamir", "_k"].concat(),
        ["shamir", "_n"].concat(),
        ["is_machine_issuer", "_active"].concat(),
        ["Household", "AddMachine"].concat(),
    ] {
        assert!(
            !production.contains(&forbidden),
            "D2a must not convert the owner-device into a machine: {forbidden}"
        );
    }
}

/// Causal proof that the production projection covers the source on BOTH sides
/// of the inline test module.
///
/// This is the defect the first D2a guard shipped with: `production_only`
/// truncated at the first `#[cfg(test)]`, so every boundary ban above was blind
/// to anything placed after `mod tests`. A banned item appended at the end of
/// the file — the cheapest possible escape — was simply never scanned.
///
/// The fixture is the minimal shape of that escape and also pins the
/// non-regression control: the single legitimate `HouseholdAddMachine` inside a
/// negative test must stay excluded. A fix that scanned the remainder without
/// delimiting the test module would trade this blind spot for a false positive,
/// so both directions are asserted here rather than only the one that failed.
#[test]
fn r0a_d2a_production_projection_covers_both_sides_of_mod_tests() {
    let fixture = concat!(
        "use crate::cbor;\n",
        "pub struct Head;\n",
        "\n",
        "#[cfg(test)]\n",
        "mod tests {\n",
        "    use super::*;\n",
        "\n",
        "    #[test]\n",
        "    fn add_machine_grant_does_not_admit_a_device() {\n",
        "        let _ = Operation::HouseholdAddMachine;\n",
        "    }\n",
        "}\n",
        "\n",
        "pub fn tail() -> std::net::IpAddr {\n",
        "    unimplemented!()\n",
        "}\n",
    );
    let production = production_only(fixture);

    // 1. The tail after `mod tests` is production and must be scannable.
    assert!(
        production.contains("pub fn tail"),
        "production after `mod tests` must survive the projection"
    );
    assert!(
        production.contains(&["std", "::net"].concat()),
        "a banned marker placed after `mod tests` must reach the boundary bans; \
         truncating at the first #[cfg(test)] is exactly the escape this guards"
    );

    // 2. The head before `mod tests` must not be traded away for the tail.
    assert!(
        production.contains("pub struct Head"),
        "production before `mod tests` must still be scanned"
    );

    // 3. Non-regression control: the in-test negative stays excluded.
    assert!(
        !production.contains(&["Household", "AddMachine"].concat()),
        "the legitimate in-test HouseholdAddMachine negative must not be \
         reported as a production leak"
    );
    assert!(
        !production.contains("#[test]"),
        "the delimited test module must be removed, not merely skipped over"
    );
}

// ─── Fatia D2b-A — atomic consume and honest commit outcomes ────────────────

#[test]
fn r0a_d2b_consume_is_a_synchronous_closure_under_the_store_lock() {
    let admission = read(package_dir().join("src/device_admission.rs"));
    let code = code_only(&admission);
    let production = production_only(&admission);

    // Arity and shape of the one sanctioned consume entry point.
    assert!(production.contains("pub fn consume_with_effect<T, E>"));
    assert!(
        production.contains("sealed: SealedDeviceAdmissionV1,"),
        "the sealed fact is taken by value so it cannot be presented twice"
    );
    assert!(production.contains("expected_peer_pub_sec1: &[u8; 33],"));
    assert!(production.contains("now: u64,"));
    assert!(
        production.contains("effect: impl FnOnce(&ConsumedDeviceAdmissionV1) -> Result<T, E>,"),
        "the effect must be a synchronous FnOnce over a borrowed token"
    );

    // The lock must be taken before the recheck and still held across `effect`.
    let entry = code
        .find("pub fn consume_with_effect")
        .expect("consume_with_effect declaration");
    let body = &code[entry..];
    let lock_at = body
        .find("StoreLock::acquire")
        .expect("consume_with_effect must acquire the store lock");
    let recheck_at = body
        .find("Self::recheck_sealed")
        .expect("consume_with_effect must recheck");
    let effect_at = body
        .find("effect(&consumed)")
        .expect("consume_with_effect must invoke the effect");
    assert!(
        lock_at < recheck_at && recheck_at < effect_at,
        "order must be lock -> recheck -> effect; got {lock_at}/{recheck_at}/{effect_at}"
    );

    // No lock-free escape hatch may coexist with it.
    assert!(
        !production.contains("pub fn consume("),
        "a lock-free `consume` returning the token would bypass the fence"
    );

    // The closure must not receive the authority: re-entering a locking method
    // would deadlock on flock, and it would let the token's scope widen.
    assert!(
        !production.contains("effect: impl FnOnce(&Self"),
        "the effect must not be handed the authority"
    );

    // Nothing async may exist in this module: the guarantee is that `.await`
    // cannot appear inside the critical section.
    for forbidden in [
        ["async", " fn"].concat(),
        ["async", " move"].concat(),
        [".", "await"].concat(),
        ["Future", "<Output"].concat(),
    ] {
        assert!(
            !production.contains(&forbidden),
            "D2b-A keeps the critical section synchronous: {forbidden}"
        );
    }

    // No escapable guard: the lock must never be handed out to a caller.
    assert!(
        !production.contains("-> StoreLock"),
        "handing a caller the lock recreates the hold-across-await hazard"
    );
    assert!(
        !production.contains("pub struct StoreLock"),
        "the lock stays private to this module"
    );

    // The point-in-time limit must stay written down next to the API.
    assert!(
        admission.contains("does **not** invalidate sessions that"),
        "the point-in-time semantics must remain documented on consume_with_effect"
    );
}

#[test]
fn r0a_d2b_commit_outcomes_cannot_report_a_landed_write_as_no_effect() {
    let admission = read(package_dir().join("src/device_admission.rs"));
    let production = production_only(&admission);

    // The honest three-state commit, and the mutation outcome that carries it.
    assert!(production.contains("pub enum DurableCommit"));
    for variant in [
        "Committed,",
        "NotCommitted { stage",
        "CommitUncertain { stage",
    ] {
        assert!(
            production.contains(variant),
            "DurableCommit must keep the {variant} arm"
        );
    }
    assert!(production.contains("pub enum CommitStage"));
    assert!(
        production.contains(
            "Uncertain {\n        attempted_generation: u64,\n        stage: CommitStage,\n    }"
        ),
        "MutationOutcome must carry an Uncertain arm naming the stage"
    );

    // `Uncertain` must not claim a settled generation, and must not carry a
    // boolean a caller could read the wrong way.
    assert!(
        production.contains("pub fn generation(self) -> Option<u64>"),
        "generation() must be Option so Uncertain cannot claim one"
    );
    assert!(
        !production.contains("applied: bool"),
        "Uncertain must carry no boolean claiming whether it applied"
    );

    // The writer must return the typed commit, never a collapsed Result.
    assert!(
        production.contains("fn atomic_replace(target: &Path, canonical: &[u8]) -> DurableCommit"),
        "atomic_replace must return DurableCommit, not Result<(), _>"
    );

    // The pre/post partition must be an exhaustive match, so a new stage cannot
    // silently default to the no-effect side.
    let classifier = struct_block(&production, "    pub fn is_pre_rename(self) -> bool {");
    assert!(
        classifier.contains("match self {"),
        "is_pre_rename must be an exhaustive match, not matches!"
    );
    assert!(
        !classifier.contains("matches!") && !classifier.contains("_ =>"),
        "is_pre_rename must not use a wildcard arm or matches!: {classifier}"
    );

    // Every post-rename stage must be classified as such.
    for post in ["ParentOpen", "ParentSync", "Readback", "ReadbackMismatch"] {
        assert!(
            classifier.contains(post),
            "post-rename stage {post} must be classified in is_pre_rename"
        );
    }
}

// ─── Fatia D2c-0 — the durable entry carries the exact device caveat set ────

#[test]
fn r0a_d2c_durable_entry_carries_the_exact_device_caveat_set() {
    let admission = read(package_dir().join("src/device_admission.rs"));
    let production = production_only(&admission);
    let entry = struct_block(&production, "pub struct DeviceAdmissionEntryV1 {");

    // Positive controls first: if these fail the block extraction moved and
    // every negative below would pass vacuously.
    for present in [
        "pub d_pub: P256PublicKey,",
        "pub device_cert_digest: Bytes32,",
        "pub narrowing_digest: Bytes32,",
    ] {
        assert!(entry.contains(present), "entry field missing: {present}");
    }

    // The set itself, under its explicit wire name — not a digest, not a flag.
    assert!(
        entry.contains("pub device_caveats: Option<Vec<Caveat>>,"),
        "the durable entry must carry the exact caveat set"
    );
    for reduced in [
        "device_caveats: bool",
        "attenuated: bool",
        "has_device_caveats",
        "device_caveats_digest",
        "device_caveats: Vec<Caveat>",
    ] {
        assert!(
            !entry.contains(reduced),
            "a marker/digest/non-optional set would lose the None vs Some([]) \
             distinction or the set itself: {reduced}"
        );
    }
    // ...and not the whole certificate, which `device_cert_digest` already binds.
    assert!(
        !entry.contains("DeviceCert"),
        "the entry must not embed the certificate"
    );

    // Admit copies the set verbatim: no unwrap_or_default, no normalization.
    assert!(
        production.contains("device_caveats: device_cert.caveats.clone(),"),
        "admit must copy the presented set exactly"
    );
    for normalizing in [
        "caveats.clone().unwrap_or_default()",
        "caveats.unwrap_or_default()",
    ] {
        assert!(
            !production.contains(normalizing),
            "no normalization: {normalizing}"
        );
    }

    // Idempotence is decided on the set too, never on the digest alone.
    assert!(
        production.contains("&& existing.device_caveats == device_cert.caveats"),
        "same_binding must compare the stored caveat set directly"
    );

    // The key must be structurally REQUIRED at decode, not merely typed as
    // `Option`. A bare `Option` field is answered by serde's missing-field
    // deserializer with `None`, and for this field `None` means "unattenuated",
    // so a dropped key would widen authority. Pinned as a property — the field
    // carries a custom decoder and is never defaulted — rather than by naming a
    // particular helper, so the implementation stays free to change.
    assert!(
        entry.contains("#[serde(deserialize_with")
            && entry.contains("pub device_caveats: Option<Vec<Caveat>>,"),
        "device_caveats must decode through a presence-requiring decoder"
    );
    for defaulted in [
        "#[serde(default)]\n    pub device_caveats",
        "#[serde(default, deserialize_with",
        "default = \"Option::default\"",
    ] {
        assert!(
            !entry.contains(defaulted),
            "device_caveats must never be defaulted: an absent key would decode \
             as None, i.e. as an unattenuated device: {defaulted}"
        );
    }
}
