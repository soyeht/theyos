#!/usr/bin/env python3
"""Tests for scripts/check-cross-repo-pin-freshness.py."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-cross-repo-pin-freshness.py")
SPEC = importlib.util.spec_from_file_location("check_cross_repo_pin_freshness", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
# Registered before exec: @dataclass resolves its annotations through
# sys.modules[cls.__module__], which is None for an unregistered module.
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)

DAY = 86400
T0 = 1_700_000_000  # fixed epoch so staleness arithmetic is deterministic

SURFACE_V1 = """\
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

/// Route-scoped settings crossing the boundary.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Clone)]
pub struct VpnNetworkSettings {
    pub addr: String,
    pub prefix_len: u8,
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum BridgeError {
    NoSession,
    TransportFailed(String),
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct ClawSession {
    inner: u8,
}

#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
impl ClawSession {
    pub async fn start_session(
        self: Arc<Self>,
        token: Vec<u8>,
    ) -> Result<u8, BridgeError> {
        Ok(0)
    }

    pub async fn status(self: Arc<Self>) -> u8 {
        0
    }
}
"""

# v2 adds one Record field. This is the smallest possible boundary move.
SURFACE_V2 = SURFACE_V1.replace(
    "    pub prefix_len: u8,\n",
    "    pub prefix_len: u8,\n    pub peer: String,\n",
)

CRATE_MANIFEST = '[package]\nname = "demo-rs"\nversion = "0.1.0"\n'


def run_git(repo: Path, *args: str, when: int | None = None) -> None:
    env = dict(os.environ)
    env.update(
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@example.invalid",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@example.invalid",
    )
    if when is not None:
        env["GIT_AUTHOR_DATE"] = f"{when} +0000"
        env["GIT_COMMITTER_DATE"] = f"{when} +0000"
    subprocess.run(
        ("git", *args), cwd=repo, env=env, check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def head(repo: Path) -> str:
    return subprocess.run(
        ("git", "rev-parse", "HEAD"), cwd=repo, check=True,
        stdout=subprocess.PIPE, text=True,
    ).stdout.strip()


def make_theyos(root: Path) -> dict[str, str]:
    """A miniature theyos: a surface crate and a few dated commits."""
    repo = root / "theyos"
    repo.mkdir()
    run_git(repo, "init", "-q", "-b", "main")
    write(repo, "admin/rust/demo-rs/Cargo.toml", CRATE_MANIFEST)
    write(repo, "admin/rust/demo-rs/src/lib.rs", SURFACE_V1)
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", "surface v1", when=T0)
    base = head(repo)

    run_git(repo, "commit", "-q", "--allow-empty", "-m", "filler", when=T0 + DAY)
    mid = head(repo)

    write(repo, "admin/rust/demo-rs/src/lib.rs", SURFACE_V2)
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", "surface v2", when=T0 + 2 * DAY)
    tip = head(repo)

    run_git(repo, "checkout", "-q", "-b", "side", base)
    run_git(repo, "commit", "-q", "--allow-empty", "-m", "abandoned", when=T0 + DAY)
    side = head(repo)
    run_git(repo, "checkout", "-q", "main")

    return {"repo": str(repo), "base": base, "mid": mid, "tip": tip, "side": side}


def make_consumer(root: Path, rev: str, *, depends_on: str | None = "demo-rs") -> Path:
    consumer = root / "consumer"
    dependency = (
        f'demo-rs = {{ git = "https://example.invalid/theyos.git", rev = "{rev}" }}\n'
        if depends_on == "demo-rs"
        else f'{depends_on} = "1"\n' if depends_on else ""
    )
    write(
        consumer,
        "Native/Ffi/Cargo.toml",
        f'[package]\nname = "ffi"\nversion = "0.1.0"\n\n[dependencies]\n{dependency}',
    )
    write(consumer, "scripts/contract.sha", f"# vendored from\n{rev}\n")
    write(consumer, "scripts/corpus.pin", f"theyos_commit={rev}\nsha256=deadbeef\n")
    return consumer


def make_manifest(
    root: Path,
    *,
    surface_files: list[str] | None = None,
    bindings: list[dict[str, object]] | None = None,
    pins: list[dict[str, object]] | None = None,
    cargo_manifests: list[str] | None = None,
) -> Path:
    paths = surface_files or ["admin/rust/demo-rs/src/lib.rs"]
    if bindings is None:
        bindings = [
            {"status": "active", "consumer": "demo-consumer", "target": "ffi"}
            for _ in paths
        ]
    if len(bindings) != len(paths):
        raise ValueError("one binding is required per synthetic surface")
    manifest = {
        "schema": checker.SCHEMA,
        "surfaces": [
            {"path": path, "binding": binding}
            for path, binding in zip(paths, bindings, strict=True)
        ],
        "consumers": [
            {
                "name": "demo-consumer",
                "targets": [
                    {
                        "name": "ffi",
                        "cargo_manifests": cargo_manifests
                        if cargo_manifests is not None
                        else ["Native/Ffi/Cargo.toml"],
                    }
                ],
                "pins": pins
                or [
                    {
                        "name": "ffi-cargo-rev",
                        "path": "Native/Ffi/Cargo.toml",
                        "kind": "cargo-git-rev",
                        "dependency": "demo-rs",
                        "governs_ffi_surface": True,
                    }
                ],
            }
        ],
    }
    path = root / "boundary.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


class Harness:
    """Points the gate at a synthetic repo instead of the live checkout."""

    def __init__(self, tmp: str) -> None:
        self.root = Path(tmp)
        self.repo = make_theyos(self.root)
        self.saved_root = checker.REPO_ROOT
        checker.REPO_ROOT = Path(self.repo["repo"])

    def restore(self) -> None:
        checker.REPO_ROOT = self.saved_root

    def run(self, **kwargs: object) -> checker.Report:
        params: dict[str, object] = {
            "target_rev": self.repo["tip"],
            "now": T0 + 2 * DAY,
            "surface_only": False,
        }
        params.update(kwargs)
        return checker.run(**params)  # type: ignore[arg-type]


class SurfaceExtractionTests(unittest.TestCase):
    """The extractor must SEE the defect before any check can catch it."""

    def test_extracts_records_enums_objects_methods_and_scaffolding(self) -> None:
        items = checker.extract_surface(SURFACE_V1)
        self.assertIn("scaffolding", items)
        self.assertIn("record VpnNetworkSettings", items)
        self.assertIn("record VpnNetworkSettings.prefix_len: u8", items)
        self.assertIn("error BridgeError::TransportFailed(String)", items)
        self.assertIn("object ClawSession", items)
        self.assertIn("method ClawSession::pub async fn status(self: Arc<Self>) -> u8", items)

    def test_multi_line_signature_keeps_its_parameters(self) -> None:
        # Regression: stopping at the first line dropped every parameter, so a
        # parameter change on the boundary read as no change at all.
        items = checker.extract_surface(SURFACE_V1)
        signature = next(item for item in items if "start_session" in item)
        self.assertIn("token: Vec<u8>", signature)

        mutated = SURFACE_V1.replace("token: Vec<u8>,", "token: Vec<u8>, now_unix: u64,")
        self.assertNotEqual(items, checker.extract_surface(mutated))

    def test_adding_a_record_field_changes_the_surface(self) -> None:
        self.assertNotEqual(checker.extract_surface(SURFACE_V1), checker.extract_surface(SURFACE_V2))

    def test_renaming_an_exported_method_changes_the_surface(self) -> None:
        mutated = SURFACE_V1.replace("pub async fn status", "pub async fn state")
        self.assertNotEqual(checker.extract_surface(SURFACE_V1), checker.extract_surface(mutated))

    def test_item_without_a_uniffi_marker_is_not_surface(self) -> None:
        items = checker.extract_surface("pub struct NotExported {\n    pub a: u8,\n}\n")
        self.assertEqual([], items)

    def test_unterminated_block_is_malformed_not_an_empty_surface(self) -> None:
        truncated = SURFACE_V1[: SURFACE_V1.index("pub prefix_len")]
        with self.assertRaises(checker.Malformed):
            checker.extract_surface(truncated)

    def test_live_surface_file_is_read_and_is_field_sensitive(self) -> None:
        # Exercised against the real bytes in the repo, not a fixture copy. A
        # read failure fails the test; it never degrades to "nothing to check".
        proc = subprocess.run(
            (
                "git", "show",
                f"origin/main:{checker.load_manifest(checker.REPO_ROOT / checker.DEFAULT_MANIFEST)['surfaces'][0]['path']}",
            ),
            cwd=checker.REPO_ROOT, check=False, stdout=subprocess.PIPE, text=True,
        )
        self.assertEqual(0, proc.returncode, "could not read the declared surface file")
        items = checker.extract_surface(proc.stdout)
        self.assertIn("record VpnNetworkSettings.prefix_len: u8", items)
        widened = checker.extract_surface(proc.stdout.replace("pub prefix_len: u8,", "pub prefix_len: u16,"))
        self.assertNotIn("record VpnNetworkSettings.prefix_len: u8", widened)


class PinParsingTests(unittest.TestCase):
    def test_parses_each_pin_spelling(self) -> None:
        rev = "a" * 40
        with tempfile.TemporaryDirectory() as tmp:
            consumer = make_consumer(Path(tmp), rev)
            cargo = {"name": "p", "path": "Native/Ffi/Cargo.toml", "kind": "cargo-git-rev", "dependency": "demo-rs"}
            bare = {"name": "p", "path": "scripts/contract.sha", "kind": "bare-rev"}
            keyed = {"name": "p", "path": "scripts/corpus.pin", "kind": "keyed-rev", "key": "theyos_commit"}
            for pin in (cargo, bare, keyed):
                with self.subTest(kind=pin["kind"]):
                    self.assertEqual(rev, checker.read_pin(consumer, pin))

    def test_unreadable_or_unparseable_pins_are_malformed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            consumer = make_consumer(root, "b" * 40)
            cases = (
                ("missing file", {"name": "p", "path": "scripts/absent.sha", "kind": "bare-rev"}),
                ("unknown kind", {"name": "p", "path": "scripts/contract.sha", "kind": "magic"}),
                (
                    "absent dependency",
                    {"name": "p", "path": "Native/Ffi/Cargo.toml", "kind": "cargo-git-rev", "dependency": "nope"},
                ),
                ("absent key", {"name": "p", "path": "scripts/corpus.pin", "kind": "keyed-rev", "key": "nope"}),
            )
            for label, pin in cases:
                with self.subTest(case=label):
                    with self.assertRaises(checker.Malformed):
                        checker.read_pin(consumer, pin)

            write(consumer, "scripts/contract.sha", "not-a-rev\n")
            with self.assertRaises(checker.Malformed):
                checker.read_pin(consumer, {"name": "p", "path": "scripts/contract.sha", "kind": "bare-rev"})

            write(consumer, "scripts/contract.sha", f"{'c' * 40}\n{'d' * 40}\n")
            with self.assertRaises(checker.Malformed):
                checker.read_pin(consumer, {"name": "p", "path": "scripts/contract.sha", "kind": "bare-rev"})


class GateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.harness = Harness(self.tmp.name)
        self.addCleanup(self.harness.restore)
        self.root = self.harness.root
        self.repo = self.harness.repo

    def assert_failure(self, report: checker.Report, needle: str) -> None:
        joined = "\n".join(report.errors)
        self.assertIn(needle, joined, f"gate did not fire; errors were: {joined or '<none>'}")

    # ── positive control ────────────────────────────────────────────────────

    def test_fresh_matching_pin_passes(self) -> None:
        consumer = make_consumer(self.root, self.repo["tip"])
        report = self.harness.run(manifest_path=make_manifest(self.root), consumer_root=consumer)
        self.assertEqual([], report.errors)

    # ── (a) ancestry ────────────────────────────────────────────────────────

    def test_pin_on_an_abandoned_branch_fails(self) -> None:
        consumer = make_consumer(self.root, self.repo["side"])
        report = self.harness.run(manifest_path=make_manifest(self.root), consumer_root=consumer)
        self.assert_failure(report, "is not an ancestor of the target rev")

    # ── (b) bounded distance ────────────────────────────────────────────────

    def test_pin_too_many_days_behind_fails(self) -> None:
        consumer = make_consumer(self.root, self.repo["tip"])
        far_future = T0 + 2 * DAY + (checker.MAX_DAYS_BEHIND + 1) * DAY
        report = self.harness.run(
            manifest_path=make_manifest(self.root), consumer_root=consumer, now=far_future
        )
        self.assert_failure(report, f"days behind (bound {checker.MAX_DAYS_BEHIND})")

    def test_pin_within_the_day_bound_does_not_fire_on_distance(self) -> None:
        consumer = make_consumer(self.root, self.repo["tip"])
        just_inside = T0 + 2 * DAY + checker.MAX_DAYS_BEHIND * DAY
        report = self.harness.run(
            manifest_path=make_manifest(self.root), consumer_root=consumer, now=just_inside
        )
        self.assertEqual([], report.errors)

    def test_pin_too_many_commits_behind_fails(self) -> None:
        consumer = make_consumer(self.root, self.repo["base"])
        saved = checker.MAX_COMMITS_BEHIND
        checker.MAX_COMMITS_BEHIND = 1
        self.addCleanup(setattr, checker, "MAX_COMMITS_BEHIND", saved)
        report = self.harness.run(manifest_path=make_manifest(self.root), consumer_root=consumer)
        self.assert_failure(report, "commits behind (bound 1)")

    def test_thresholds_are_the_measured_values_and_have_not_expired(self) -> None:
        # A silent edit of these numbers is exactly the failure mode the gate
        # exists to stop, so it has to show up as a test diff.
        self.assertEqual(14, checker.MAX_DAYS_BEHIND)
        self.assertEqual(400, checker.MAX_COMMITS_BEHIND)
        self.assertEqual(7, checker.MAX_PIN_SPREAD_DAYS)
        self.assertLess(checker.THRESHOLD_MEASURED_ON, checker.THRESHOLD_REVIEW_BY)

    def test_expired_thresholds_fail_the_gate(self) -> None:
        consumer = make_consumer(self.root, self.repo["tip"])
        saved = checker.THRESHOLD_REVIEW_BY
        checker.THRESHOLD_REVIEW_BY = "1971-01-01"
        self.addCleanup(setattr, checker, "THRESHOLD_REVIEW_BY", saved)
        report = self.harness.run(manifest_path=make_manifest(self.root), consumer_root=consumer)
        self.assert_failure(report, "expired on")

    # ── (c) FFI surface drift ───────────────────────────────────────────────

    def test_surface_added_since_the_pin_fails_even_when_the_pin_is_fresh(self) -> None:
        # The pin is one commit and one day old -- inside every distance bound.
        consumer = make_consumer(self.root, self.repo["mid"])
        report = self.harness.run(manifest_path=make_manifest(self.root), consumer_root=consumer)
        self.assert_failure(report, "FFI surface ADDED since the pin")
        self.assert_failure(report, "record VpnNetworkSettings.peer: String")

    def test_surface_removed_since_the_pin_fails(self) -> None:
        consumer = make_consumer(self.root, self.repo["tip"])
        run_git(Path(self.repo["repo"]), "checkout", "-q", self.repo["mid"], "--", "admin/rust/demo-rs/src/lib.rs")
        run_git(Path(self.repo["repo"]), "add", "-A")
        run_git(Path(self.repo["repo"]), "commit", "-q", "-m", "revert surface", when=T0 + 3 * DAY)
        report = self.harness.run(
            manifest_path=make_manifest(self.root), consumer_root=consumer,
            target_rev=head(Path(self.repo["repo"])), now=T0 + 3 * DAY,
        )
        self.assert_failure(report, "FFI surface REMOVED since the pin")

    def test_pin_predating_the_whole_surface_file_fails(self) -> None:
        # Failure 1 in miniature: the consumer pins a rev at which the crate
        # carrying the boundary does not exist yet.
        repo = Path(self.repo["repo"])
        write(repo, "admin/rust/late-rs/Cargo.toml", '[package]\nname = "late-rs"\nversion = "0.1.0"\n')
        write(repo, "admin/rust/late-rs/src/lib.rs", SURFACE_V1)
        run_git(repo, "add", "-A")
        run_git(repo, "commit", "-q", "-m", "late surface crate", when=T0 + 3 * DAY)
        tip = head(repo)
        consumer = make_consumer(self.root, self.repo["tip"])
        write(
            consumer,
            "Native/Ffi/Cargo.toml",
            '[package]\nname = "ffi"\nversion = "0.1.0"\n\n[dependencies]\n'
            f'demo-rs = {{ git = "https://example.invalid/theyos.git", rev = "{self.repo["tip"]}" }}\n'
            'late-rs = { path = "../late" }\n',
        )
        manifest = make_manifest(
            self.root,
            surface_files=["admin/rust/demo-rs/src/lib.rs", "admin/rust/late-rs/src/lib.rs"],
        )
        report = self.harness.run(
            manifest_path=manifest, consumer_root=consumer, target_rev=tip, now=T0 + 3 * DAY
        )
        self.assert_failure(report, "predates admin/rust/late-rs/src/lib.rs entirely")

    # ── (d) pin agreement ───────────────────────────────────────────────────

    def test_shell_assigned_rev_is_read_from_the_build_script(self) -> None:
        """The pin that governs the surface can live in a shell script.

        This kind exists because the real consumer moved it there: its
        `Cargo.toml` declares a path dependency on a vendored checkout, and the
        immutable rev is assigned in the script that populates it. A gate that
        only parsed `Cargo.toml` read a dependency form the consumer no longer
        used and reported a rev weeks staler than the live one.
        """
        repo = Path(self.repo["repo"])
        tip = head(repo)
        consumer = make_consumer(self.root, tip)
        write(
            consumer,
            "Scripts/build.sh",
            f'#!/usr/bin/env bash\nset -euo pipefail\nSOURCE_REV="{tip}"\n',
        )
        pins = [
            {"name": "vendored-source-rev", "path": "Scripts/build.sh",
             "kind": "shell-assigned-rev", "variable": "SOURCE_REV",
             "governs_ffi_surface": True},
        ]
        report = self.harness.run(
            manifest_path=make_manifest(self.root, pins=pins), consumer_root=consumer,
            target_rev=tip, now=T0,
        )
        self.assertEqual([], report.errors)

    def test_shell_assigned_rev_rejects_an_ambiguous_assignment(self) -> None:
        """Two assignments is malformed input, not a value to pick from.

        Reading the first (or the last) would make the gate's answer depend on
        line order in somebody else's script.
        """
        repo = Path(self.repo["repo"])
        tip = head(repo)
        consumer = make_consumer(self.root, tip)
        write(
            consumer,
            "Scripts/build.sh",
            f'SOURCE_REV="{tip}"\nSOURCE_REV="{self.repo["base"]}"\n',
        )
        with self.assertRaises(checker.Malformed):
            checker.read_pin(
                consumer,
                {"name": "p", "path": "Scripts/build.sh",
                 "kind": "shell-assigned-rev", "variable": "SOURCE_REV"},
            )

    def test_shell_assigned_rev_absent_variable_cannot_evaluate(self) -> None:
        """A script that stopped assigning the variable must not read as clean.

        This is the shape the whole gate exists to refuse: an input that went
        away is an unanswered question, never a pass.
        """
        repo = Path(self.repo["repo"])
        tip = head(repo)
        consumer = make_consumer(self.root, tip)
        write(consumer, "Scripts/build.sh", "#!/usr/bin/env bash\nset -euo pipefail\n")
        with self.assertRaises(checker.Malformed):
            checker.read_pin(
                consumer,
                {"name": "p", "path": "Scripts/build.sh",
                 "kind": "shell-assigned-rev", "variable": "SOURCE_REV"},
            )

    def test_pins_spread_too_far_apart_are_named(self) -> None:
        repo = Path(self.repo["repo"])
        run_git(repo, "commit", "-q", "--allow-empty", "-m", "later",
                when=T0 + (checker.MAX_PIN_SPREAD_DAYS + 3) * DAY)
        tip = head(repo)
        consumer = make_consumer(self.root, tip)
        write(consumer, "scripts/contract.sha", f"{self.repo['base']}\n")
        pins = [
            {"name": "ffi-cargo-rev", "path": "Native/Ffi/Cargo.toml", "kind": "cargo-git-rev",
             "dependency": "demo-rs", "governs_ffi_surface": True},
            {"name": "contract-sha", "path": "scripts/contract.sha", "kind": "bare-rev",
             "governs_ffi_surface": False},
        ]
        report = self.harness.run(
            manifest_path=make_manifest(self.root, pins=pins), consumer_root=consumer,
            target_rev=tip, now=T0 + (checker.MAX_PIN_SPREAD_DAYS + 3) * DAY,
        )
        self.assert_failure(report, "pins disagree across")
        self.assert_failure(report, "contract-sha=")

    def test_pins_that_agree_are_reported_as_agreeing(self) -> None:
        consumer = make_consumer(self.root, self.repo["tip"])
        write(consumer, "scripts/contract.sha", f"{self.repo['tip']}\n")
        pins = [
            {"name": "ffi-cargo-rev", "path": "Native/Ffi/Cargo.toml", "kind": "cargo-git-rev",
             "dependency": "demo-rs", "governs_ffi_surface": True},
            {"name": "contract-sha", "path": "scripts/contract.sha", "kind": "bare-rev",
             "governs_ffi_surface": False},
        ]
        report = self.harness.run(manifest_path=make_manifest(self.root, pins=pins), consumer_root=consumer)
        self.assertEqual([], report.errors)
        self.assertTrue(any("pins agree" in note for note in report.notes))

    # ── (e) surface-crate coverage ──────────────────────────────────────────

    def test_consumer_not_depending_on_a_surface_crate_fails(self) -> None:
        consumer = make_consumer(self.root, self.repo["tip"])
        write(
            consumer,
            "Native/Ffi/Cargo.toml",
            '[package]\nname = "ffi"\nversion = "0.1.0"\n\n[dependencies]\nunrelated = "1"\n',
        )
        write(consumer, "scripts/contract.sha", f"{self.repo['tip']}\n")
        pins = [
            {
                "name": "contract-sha",
                "path": "scripts/contract.sha",
                "kind": "bare-rev",
                "governs_ffi_surface": True,
            }
        ]
        report = self.harness.run(manifest_path=make_manifest(self.root, pins=pins), consumer_root=consumer)
        self.assert_failure(report, "is bound to admin/rust/demo-rs/src/lib.rs but does not depend")

    def test_deferred_surface_does_not_infer_a_consumer_binding(self) -> None:
        consumer = make_consumer(self.root, self.repo["tip"], depends_on=None)
        binding = {
            "status": "deferred",
            "owner": "boundary-owner",
            "reason": "No current target builds this distinct FFI surface.",
            "expires": "2099-01-01",
        }
        pins = [
            {
                "name": "contract-sha",
                "path": "scripts/contract.sha",
                "kind": "bare-rev",
                "governs_ffi_surface": False,
            }
        ]
        report = self.harness.run(
            manifest_path=make_manifest(self.root, bindings=[binding], pins=pins),
            consumer_root=consumer,
        )
        self.assertEqual([], report.errors)
        self.assertTrue(any("explicitly deferred" in note for note in report.notes))

    def test_expired_deferred_surface_is_red(self) -> None:
        consumer = make_consumer(self.root, self.repo["tip"], depends_on=None)
        binding = {
            "status": "deferred",
            "owner": "boundary-owner",
            "reason": "No current target builds this surface.",
            "expires": "2000-01-01",
        }
        pins = [
            {
                "name": "contract-sha",
                "path": "scripts/contract.sha",
                "kind": "bare-rev",
                "governs_ffi_surface": False,
            }
        ]
        report = self.harness.run(
            manifest_path=make_manifest(self.root, bindings=[binding], pins=pins),
            consumer_root=consumer,
        )
        self.assert_failure(report, "deferred surface admin/rust/demo-rs/src/lib.rs expired")

    def test_active_binding_requires_a_real_target_and_governing_pin(self) -> None:
        good = json.loads(make_manifest(self.root).read_text(encoding="utf-8"))
        path = self.root / "bad-binding.json"
        cases = {
            "unknown target": {
                **good,
                "surfaces": [{
                    "path": "admin/rust/demo-rs/src/lib.rs",
                    "binding": {"status": "active", "consumer": "demo-consumer", "target": "absent"},
                }],
            },
            "no governing pin": {
                **good,
                "consumers": [{
                    **good["consumers"][0],
                    "pins": [{
                        "name": "contract-sha",
                        "path": "scripts/contract.sha",
                        "kind": "bare-rev",
                        "governs_ffi_surface": False,
                    }],
                }],
            },
        }
        for label, payload in cases.items():
            with self.subTest(case=label):
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(checker.Malformed):
                    checker.load_manifest(path)

    # ── sweep: the declared list must equal the tree ─────────────────────────

    def test_undeclared_surface_file_fails_the_sweep(self) -> None:
        repo = Path(self.repo["repo"])
        write(repo, "admin/rust/new-rs/Cargo.toml", '[package]\nname = "new-rs"\nversion = "0.1.0"\n')
        write(repo, "admin/rust/new-rs/src/lib.rs", SURFACE_V1)
        run_git(repo, "add", "-A")
        run_git(repo, "commit", "-q", "-m", "undeclared surface", when=T0 + 3 * DAY)
        tip = head(repo)
        consumer = make_consumer(self.root, tip)
        report = self.harness.run(
            manifest_path=make_manifest(self.root), consumer_root=consumer,
            target_rev=tip, now=T0 + 3 * DAY,
        )
        self.assert_failure(report, "admin/rust/new-rs/src/lib.rs carries uniffi cross-repo surface")

    def test_declared_surface_that_lost_its_markers_fails(self) -> None:
        repo = Path(self.repo["repo"])
        write(repo, "admin/rust/demo-rs/src/lib.rs", "pub struct Plain { pub a: u8 }\n")
        run_git(repo, "add", "-A")
        run_git(repo, "commit", "-q", "-m", "surface gone", when=T0 + 3 * DAY)
        tip = head(repo)
        consumer = make_consumer(self.root, tip)
        report = self.harness.run(
            manifest_path=make_manifest(self.root), consumer_root=consumer,
            target_rev=tip, now=T0 + 3 * DAY,
        )
        self.assert_failure(report, "carries no uniffi markers at the target rev")

    def test_empty_sweep_is_a_broken_instrument_not_a_clean_tree(self) -> None:
        saved = checker.UNIFFI_SWEEP_ERE
        checker.UNIFFI_SWEEP_ERE = "zzz_no_such_token_zzz"
        self.addCleanup(setattr, checker, "UNIFFI_SWEEP_ERE", saved)
        consumer = make_consumer(self.root, self.repo["tip"])
        report = self.harness.run(manifest_path=make_manifest(self.root), consumer_root=consumer)
        self.assert_failure(report, "a search that finds nothing is a broken instrument")

    def test_declared_surface_missing_from_the_tree_fails(self) -> None:
        consumer = make_consumer(self.root, self.repo["tip"])
        manifest = make_manifest(
            self.root, surface_files=["admin/rust/demo-rs/src/lib.rs", "admin/rust/ghost-rs/src/lib.rs"]
        )
        report = self.harness.run(manifest_path=manifest, consumer_root=consumer)
        self.assert_failure(report, "does not exist at the target rev")

    # ── fail closed ─────────────────────────────────────────────────────────

    def test_absent_consumer_cannot_evaluate_and_never_passes(self) -> None:
        manifest = make_manifest(self.root)
        with self.assertRaises(checker.CannotEvaluate):
            self.harness.run(manifest_path=manifest, consumer_root=None)
        with self.assertRaises(checker.CannotEvaluate):
            self.harness.run(manifest_path=manifest, consumer_root=self.root / "absent")

    def test_unknown_pin_rev_cannot_evaluate(self) -> None:
        consumer = make_consumer(self.root, "e" * 40)
        with self.assertRaises(checker.CannotEvaluate):
            self.harness.run(manifest_path=make_manifest(self.root), consumer_root=consumer)

    def test_malformed_manifests_are_rejected(self) -> None:
        good = json.loads(make_manifest(self.root).read_text(encoding="utf-8"))
        cases: dict[str, object] = {
            "wrong schema": {**good, "schema": "other"},
            "no surfaces": {**good, "surfaces": []},
            "surface not a list": {**good, "surfaces": "one"},
            "surface without binding": {
                **good,
                "surfaces": [{"path": "admin/rust/demo-rs/src/lib.rs"}],
            },
            "deferred without owner": {
                **good,
                "surfaces": [{
                    "path": "admin/rust/demo-rs/src/lib.rs",
                    "binding": {
                        "status": "deferred",
                        "reason": "not wired",
                        "expires": "2099-01-01",
                    },
                }],
            },
            "no consumers": {**good, "consumers": []},
            "consumer without pins": {**good, "consumers": [{"name": "x", "pins": []}]},
            "not an object": [good],
        }
        path = self.root / "bad.json"
        for label, payload in cases.items():
            with self.subTest(case=label):
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(checker.Malformed):
                    checker.load_manifest(path)

        path.write_text("{ not json", encoding="utf-8")
        with self.assertRaises(checker.Malformed):
            checker.load_manifest(path)
        with self.assertRaises(checker.Malformed):
            checker.load_manifest(self.root / "does-not-exist.json")

    def test_surface_only_reports_what_it_did_not_check(self) -> None:
        report = self.harness.run(
            manifest_path=make_manifest(self.root), consumer_root=None, surface_only=True
        )
        self.assertEqual([], report.errors)
        self.assertTrue(report.unchecked)
        self.assertTrue(any("pin ancestry" in item for item in report.unchecked))


class CliTests(unittest.TestCase):
    """Exit-code discipline, measured through the real CLI on the real repo."""

    def cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    def test_missing_consumer_exits_cannot_evaluate_not_zero(self) -> None:
        proc = self.cli()
        self.assertEqual(checker.EXIT_CANNOT_EVALUATE, proc.returncode, proc.stderr)
        self.assertIn("CANNOT EVALUATE", proc.stderr)

    def test_missing_manifest_exits_malformed(self) -> None:
        proc = self.cli("--manifest", "/nonexistent/boundary.json", "--surface-only")
        self.assertEqual(checker.EXIT_MALFORMED, proc.returncode, proc.stderr)

    def test_unknown_target_rev_exits_cannot_evaluate(self) -> None:
        proc = self.cli("--surface-only", "--target-rev", "no/such/rev")
        self.assertEqual(checker.EXIT_CANNOT_EVALUATE, proc.returncode, proc.stderr)

    def test_surface_only_passes_on_the_live_tree_and_says_it_is_partial(self) -> None:
        proc = self.cli("--surface-only")
        self.assertEqual(checker.EXIT_OK, proc.returncode, proc.stderr)
        self.assertIn("OK (PARTIAL)", proc.stdout)
        self.assertIn("NOT CHECKED", proc.stdout)

    def test_live_manifest_declares_the_real_surface(self) -> None:
        proc = self.cli("--print-surface")
        self.assertEqual(checker.EXIT_OK, proc.returncode, proc.stderr)
        self.assertIn("record VpnNetworkSettings", proc.stdout)
        self.assertNotIn("MISSING", proc.stdout)

    def test_output_never_echoes_a_path_outside_the_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            consumer = make_consumer(root, "f" * 40)
            proc = self.cli("--consumer-repo", str(consumer))
            self.assertNotEqual(checker.EXIT_OK, proc.returncode)
            self.assertNotIn(str(consumer), proc.stdout + proc.stderr)
            self.assertNotIn(tmp, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
