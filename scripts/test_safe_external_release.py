#!/usr/bin/env python3
"""Stateful adversarial tests for governed iOS release and draft-PR adapters.

The fake API implements the same read/mutate boundary as the production client.
Every success case asserts exactly one mutation. Precondition rejections assert
zero; post-mutation readback mutants assert one mutation and a RED result. No
test can reach GitHub.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping
from unittest import mock

import safe_external_write as guard


TARGET = "1" * 40
MAIN = "2" * 40
TAG_OBJECT = "3" * 40
WRONG = "4" * 40
VERSION = "0.1.19"
TAG = f"mac-v{VERSION}"
TAG_REF = f"refs/tags/{TAG}"
TAG_MESSAGE = f"Soyeht {VERSION}\n"


class FakeReleaseAPI:
    def __init__(self) -> None:
        self.main_oid = MAIN
        self.target_oid = TARGET
        self.compare_status = "ahead"
        self.merge_base = TARGET
        self.branch_exists = False
        self.project = b"\n".join(
            [b"MARKETING_VERSION = 0.1.19;" for _ in range(12)]
        )
        self.workflow = b"\n".join(
            (
                guard.RELEASE_CONTRACT_MARKER,
                guard.RELEASE_REQUIRED_BUILD_MARKER,
                b"      expected_ref:",
                b"      expected_oid:",
                b"  contents: read",
                b"        uses: actions/upload-artifact@v4",
                b"          if-no-files-found: error",
            )
        )
        self.execution_contract = {
            path: f"reviewed bytes for {path}\n".encode("utf-8")
            for path in guard.RELEASE_EXECUTION_CONTRACT_SHA256
            if path != guard.RELEASE_WORKFLOW_FILE
        }
        self.tag_objects: dict[str, dict[str, Any]] = {}
        self.tags: dict[str, str] = {}
        self.releases: dict[int, dict[str, Any]] = {}
        self.assets: dict[int, dict[str, Any]] = {}
        self.mutations: list[tuple[str, str]] = []
        self.next_release_id = 71
        self.next_asset_id = 91
        self.tag_object_readback_override: dict[str, Any] | None = None
        self.tag_ref_readback_override: dict[str, Any] | None = None
        self.release_readback_patch: dict[str, Any] | None = None
        self.asset_readback_override: dict[str, Any] | None = None
        self.linewrap_contents = False

    def add_tag(self, *, object_type: str = "tag", target: str = TARGET) -> None:
        self.tag_objects[TAG_OBJECT] = {
            "sha": TAG_OBJECT,
            "tag": TAG,
            "message": TAG_MESSAGE,
            "object": {"type": "commit", "sha": target},
        }
        if object_type == "tag":
            self.tags[TAG] = TAG_OBJECT
        else:
            self.tags[TAG] = target

    def add_release(self, *, draft: bool = True, target: str = TARGET) -> int:
        release_id = self.next_release_id
        self.next_release_id += 1
        self.releases[release_id] = {
            "id": release_id,
            "tag_name": TAG,
            "target_commitish": target,
            "name": f"Soyeht macOS {VERSION}",
            "body": "Release body\n",
            "draft": draft,
            "prerelease": False,
            "assets": [],
            "upload_url": (
                f"https://uploads.github.com/repos/{guard.RELEASE_GITHUB_REPO}/"
                f"releases/{release_id}/assets{{?name,label}}"
            ),
        }
        return release_id

    def add_asset(self, release_id: int, name: str, payload: bytes) -> dict[str, Any]:
        asset_id = self.next_asset_id
        self.next_asset_id += 1
        value = {
            "id": asset_id,
            "name": name,
            "size": len(payload),
            "digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
            "state": "uploaded",
        }
        self.assets[asset_id] = value
        self.releases[release_id]["assets"].append(value)
        return value

    def read_optional(self, endpoint: str) -> Any | None:
        if endpoint.endswith(f"/git/ref/heads/{TAG}"):
            if self.branch_exists:
                return {
                    "ref": f"refs/heads/{TAG}",
                    "object": {"type": "commit", "sha": TARGET},
                }
            return None
        if endpoint.endswith(f"/git/ref/tags/{TAG}"):
            return self._tag_ref() if TAG in self.tags else None
        if endpoint.endswith(f"/releases/tags/{TAG}"):
            return next(
                (copy.deepcopy(value) for value in self.releases.values()), None
            )
        raise AssertionError(f"unexpected optional read: {endpoint}")

    def read_pages(self, endpoint: str) -> list[Any]:
        self.assert_repo(endpoint)
        if "/releases?per_page=100" not in endpoint:
            raise AssertionError(f"unexpected paginated read: {endpoint}")
        return copy.deepcopy(list(self.releases.values()))

    def _tag_ref(self) -> dict[str, Any]:
        if self.tag_ref_readback_override is not None:
            return copy.deepcopy(self.tag_ref_readback_override)
        oid = self.tags[TAG]
        object_type = "tag" if oid in self.tag_objects else "commit"
        return {
            "ref": TAG_REF,
            "object": {"type": object_type, "sha": oid},
        }

    def assert_repo(self, endpoint: str) -> None:
        if not endpoint.startswith(f"repos/{guard.RELEASE_GITHUB_REPO}/"):
            raise AssertionError(f"un-pinned API endpoint: {endpoint}")

    def read(self, endpoint: str) -> Any:
        self.assert_repo(endpoint)
        if endpoint.endswith("/git/ref/heads/main"):
            return {
                "ref": "refs/heads/main",
                "object": {"type": "commit", "sha": self.main_oid},
            }
        if endpoint.endswith(f"/commits/{TARGET}"):
            return {"sha": self.target_oid}
        if endpoint.endswith(f"/compare/{TARGET}...{MAIN}"):
            return {
                "status": self.compare_status,
                "merge_base_commit": {"sha": self.merge_base},
            }
        if f"/contents/{guard.RELEASE_PROJECT_FILE}?ref={TARGET}" in endpoint:
            encoded = base64.b64encode(self.project).decode("ascii")
            if self.linewrap_contents:
                encoded = "\n".join(encoded[index : index + 20] for index in range(0, len(encoded), 20))
            return {
                "type": "file",
                "encoding": "base64",
                "content": encoded,
            }
        for path in guard.RELEASE_EXECUTION_CONTRACT_SHA256:
            if f"/contents/{path}?ref={TARGET}" not in endpoint:
                continue
            payload = (
                self.workflow
                if path == guard.RELEASE_WORKFLOW_FILE
                else self.execution_contract[path]
            )
            encoded = base64.b64encode(payload).decode("ascii")
            if self.linewrap_contents:
                encoded = "\n".join(encoded[index : index + 20] for index in range(0, len(encoded), 20))
            return {
                "type": "file",
                "encoding": "base64",
                "content": encoded,
            }
        if endpoint.endswith(f"/git/ref/tags/{TAG}") and TAG in self.tags:
            return self._tag_ref()
        if "/git/tags/" in endpoint:
            oid = endpoint.rsplit("/", 1)[1]
            if self.tag_object_readback_override is not None:
                return copy.deepcopy(self.tag_object_readback_override)
            return copy.deepcopy(self.tag_objects[oid])
        if "/releases/assets/" in endpoint:
            asset_id = int(endpoint.rsplit("/", 1)[1])
            if self.asset_readback_override is not None:
                return copy.deepcopy(self.asset_readback_override)
            return copy.deepcopy(self.assets[asset_id])
        if "/releases/" in endpoint and endpoint.rsplit("/", 1)[1].isdigit():
            release_id = int(endpoint.rsplit("/", 1)[1])
            value = copy.deepcopy(self.releases[release_id])
            if self.mutations and self.release_readback_patch is not None:
                value.update(copy.deepcopy(self.release_readback_patch))
            return value
        raise AssertionError(f"unexpected read: {endpoint}")

    def mutate_json(
        self, method: str, endpoint: str, payload: Mapping[str, Any]
    ) -> Any:
        self.assert_repo(endpoint)
        self.mutations.append((method, endpoint))
        if endpoint.endswith("/git/tags"):
            value = {
                "sha": TAG_OBJECT,
                "tag": payload["tag"],
                "message": payload["message"],
                "object": {"type": payload["type"], "sha": payload["object"]},
            }
            self.tag_objects[TAG_OBJECT] = value
            return copy.deepcopy(value)
        if endpoint.endswith("/git/refs"):
            self.tags[TAG] = str(payload["sha"])
            return self._tag_ref()
        if endpoint.endswith("/releases") and method == "POST":
            release_id = self.next_release_id
            self.next_release_id += 1
            value = {
                "id": release_id,
                "tag_name": payload["tag_name"],
                "target_commitish": payload["target_commitish"],
                "name": payload["name"],
                "body": payload["body"],
                "draft": payload["draft"],
                "prerelease": payload["prerelease"],
                "assets": [],
                "upload_url": (
                    f"https://uploads.github.com/repos/{guard.RELEASE_GITHUB_REPO}/"
                    f"releases/{release_id}/assets{{?name,label}}"
                ),
            }
            self.releases[release_id] = value
            return copy.deepcopy(value)
        if "/releases/" in endpoint and method == "PATCH":
            release_id = int(endpoint.rsplit("/", 1)[1])
            self.releases[release_id]["draft"] = bool(payload["draft"])
            return copy.deepcopy(self.releases[release_id])
        raise AssertionError(f"unexpected mutation: {method} {endpoint}")

    def upload_asset(
        self,
        release_id: int,
        name: str,
        payload: bytes,
        upload_url: str,
    ) -> Any:
        self.assertEqualUploadURL(release_id, upload_url)
        self.mutations.append(
            ("POST", f"repos/{guard.RELEASE_GITHUB_REPO}/releases/{release_id}/assets")
        )
        return copy.deepcopy(self.add_asset(release_id, name, payload))

    def assertEqualUploadURL(self, release_id: int, upload_url: str) -> None:
        expected = (
            f"https://uploads.github.com/repos/{guard.RELEASE_GITHUB_REPO}/"
            f"releases/{release_id}/assets{{?name,label}}"
        )
        if upload_url != expected:
            raise AssertionError(f"unexpected upload URL: {upload_url}")


class FakeIOSPRAPI:
    def __init__(self) -> None:
        self.head_oid = TARGET
        self.post_mutation_head_oid: str | None = None
        self.head_type = "commit"
        self.head_ref = f"refs/heads/{guard.IOS_PR_HEAD}"
        self.existing_prs: list[dict[str, Any]] = []
        self.mutations: list[tuple[str, str, dict[str, Any]]] = []
        self.readback_patch: dict[str, Any] | None = None
        self.created_number: Any = 27
        self.created_pr: dict[str, Any] | None = None

    def _assert_repo(self, endpoint: str) -> None:
        if not endpoint.startswith(f"repos/{guard.RELEASE_GITHUB_REPO}/"):
            raise AssertionError(f"un-pinned iOS PR endpoint: {endpoint}")

    def read(self, endpoint: str) -> Any:
        self._assert_repo(endpoint)
        if endpoint.endswith(f"/git/ref/heads/{guard.IOS_PR_HEAD}"):
            oid = (
                self.post_mutation_head_oid
                if self.mutations and self.post_mutation_head_oid is not None
                else self.head_oid
            )
            return {
                "ref": self.head_ref,
                "object": {"type": self.head_type, "sha": oid},
            }
        if endpoint.endswith(f"/pulls/{self.created_number}"):
            if self.created_pr is None:
                raise AssertionError("PR readback occurred before mutation")
            value = copy.deepcopy(self.created_pr)
            if self.readback_patch is not None:
                for key, replacement in self.readback_patch.items():
                    if key == "head.repo.full_name":
                        value["head"]["repo"]["full_name"] = replacement
                    elif key == "base.repo.full_name":
                        value["base"]["repo"]["full_name"] = replacement
                    elif key.startswith("head."):
                        value["head"][key.removeprefix("head.")] = replacement
                    elif key.startswith("base."):
                        value["base"][key.removeprefix("base.")] = replacement
                    else:
                        value[key] = replacement
            return value
        raise AssertionError(f"unexpected iOS PR read: {endpoint}")

    def read_pages(self, endpoint: str) -> list[Any]:
        self._assert_repo(endpoint)
        expected_head = "soyeht%3Aci%2Fgoverned-macos-release"
        expected = (
            f"repos/{guard.RELEASE_GITHUB_REPO}/pulls?state=all&head={expected_head}"
            f"&base={guard.IOS_PR_BASE}&per_page=100"
        )
        if endpoint != expected:
            raise AssertionError(f"unexpected iOS PR listing: {endpoint}")
        return copy.deepcopy(self.existing_prs)

    def mutate_json(
        self, method: str, endpoint: str, payload: Mapping[str, Any]
    ) -> Any:
        self._assert_repo(endpoint)
        stored_payload = dict(payload)
        self.mutations.append((method, endpoint, stored_payload))
        if method != "POST" or endpoint != f"repos/{guard.RELEASE_GITHUB_REPO}/pulls":
            raise AssertionError(f"unexpected iOS PR mutation: {method} {endpoint}")
        self.created_pr = {
            "number": self.created_number,
            "state": "open",
            "draft": stored_payload["draft"],
            "title": stored_payload["title"],
            "body": stored_payload["body"],
            "head": {
                "ref": guard.IOS_PR_HEAD,
                "sha": self.head_oid,
                "repo": {"full_name": guard.RELEASE_GITHUB_REPO},
            },
            "base": {
                "ref": guard.IOS_PR_BASE,
                "repo": {"full_name": guard.RELEASE_GITHUB_REPO},
            },
        }
        return {"number": self.created_number}


class GovernedIOSPRCreateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = FakeIOSPRAPI()
        self.title = "ci(ios): govern the macOS release path"
        self.body = "Draft consumer body\n"

    def arguments(self, *extra: str) -> list[str]:
        return [
            "--expected-head-oid",
            TARGET,
            "--title",
            self.title,
            *extra,
        ]

    def execute(self) -> int:
        return guard.execute_governed_ios_pr_create(
            self.arguments(), self.body, api=self.api
        )

    def test_success_is_one_fixed_repo_draft_mutation_with_exact_readback(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(0, self.execute())
        self.assertEqual(
            [
                (
                    "POST",
                    f"repos/{guard.RELEASE_GITHUB_REPO}/pulls",
                    {
                        "base": "main",
                        "body": self.body,
                        "draft": True,
                        "head": "soyeht:ci/governed-macos-release",
                        "title": self.title,
                    },
                )
            ],
            self.api.mutations,
        )
        receipt = json.loads(stdout.getvalue())
        self.assertEqual("soyeht/soyeht-ios", receipt["repository"])
        self.assertIs(True, receipt["draft"])
        self.assertEqual(TARGET, receipt["head_oid"])

    def test_repo_base_head_and_destination_overrides_are_not_in_grammar(self) -> None:
        for flag in (
            "--repo",
            "--host",
            "--dest",
            "--base",
            "--head",
            "--draft",
            "--force",
            "--admin",
        ):
            with self.subTest(flag=flag), self.assertRaises(guard.UnsafeCommand):
                guard.execute_governed_ios_pr_create(
                    self.arguments(flag, "attacker/value"), self.body, api=self.api
                )
        self.assertEqual([], self.api.mutations)

    def test_argument_shape_title_and_full_oid_fail_closed(self) -> None:
        cases = (
            [],
            ["--expected-head-oid", TARGET],
            ["--title", self.title],
            ["--expected-head-oid", TARGET, "--expected-head-oid", TARGET, "--title", self.title],
            ["--expected-head-oid", TARGET, "--title", self.title, "--title", self.title],
            ["--expected-head-oid", "a" * 39, "--title", self.title],
            ["--expected-head-oid", "A" * 40, "--title", self.title],
            ["--expected-head-oid", TARGET, "--title", ""],
            ["--expected-head-oid", TARGET, "--title", "two\nlines"],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(
                (guard.UnsafeCommand, guard.ReleaseGuardError)
            ):
                guard.execute_governed_ios_pr_create(
                    arguments, self.body, api=self.api
                )
        with self.assertRaises(guard.ReleaseGuardError):
            guard.execute_governed_ios_pr_create(
                self.arguments(), "", api=self.api
            )
        self.assertEqual([], self.api.mutations)

    def test_remote_ref_name_type_and_oid_mismatch_block_before_mutation(self) -> None:
        mutations = (
            lambda api: setattr(api, "head_ref", "refs/heads/other"),
            lambda api: setattr(api, "head_type", "tag"),
            lambda api: setattr(api, "head_oid", WRONG),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.api = FakeIOSPRAPI()
                mutate(self.api)
                with self.assertRaises(guard.ReleaseGuardError):
                    self.execute()
                self.assertEqual([], self.api.mutations)

    def test_any_existing_pr_blocks_before_mutation(self) -> None:
        for state, draft in (("open", True), ("open", False), ("closed", True)):
            with self.subTest(state=state, draft=draft):
                self.api = FakeIOSPRAPI()
                self.api.existing_prs = [{"number": 4, "state": state, "draft": draft}]
                with self.assertRaises(guard.ReleaseGuardError):
                    self.execute()
                self.assertEqual([], self.api.mutations)

    def test_post_mutation_remote_ref_drift_is_red_after_one_mutation(self) -> None:
        self.api.post_mutation_head_oid = WRONG
        with self.assertRaisesRegex(guard.ReleaseGuardError, "remote branch"):
            self.execute()
        self.assertEqual(1, len(self.api.mutations))

    def test_created_number_mismatch_is_red_after_one_mutation(self) -> None:
        for number in (None, True, 0, -1, "27"):
            with self.subTest(number=number):
                self.api = FakeIOSPRAPI()
                self.api.created_number = number
                with self.assertRaises(guard.ReleaseGuardError):
                    self.execute()
                self.assertEqual(1, len(self.api.mutations))

    def test_every_readback_field_is_load_bearing(self) -> None:
        patches = (
            {"number": 99},
            {"state": "closed"},
            {"draft": False},
            {"title": "changed"},
            {"body": "changed\n"},
            {"head.ref": "other"},
            {"head.sha": WRONG},
            {"head.repo.full_name": "other/repo"},
            {"base.ref": "other"},
            {"base.repo.full_name": "other/repo"},
        )
        for patch in patches:
            with self.subTest(patch=patch):
                self.api = FakeIOSPRAPI()
                self.api.readback_patch = patch
                with self.assertRaisesRegex(guard.ReleaseGuardError, "readback"):
                    self.execute()
                self.assertEqual(1, len(self.api.mutations))

    def test_main_routes_exact_validated_body_and_title_to_dedicated_adapter(self) -> None:
        stdin = mock.Mock()
        stdin.buffer.read.return_value = self.body.encode("utf-8")
        with (
            mock.patch.object(guard.sys, "stdin", stdin),
            mock.patch.object(
                guard,
                "execute_governed_ios_pr_create",
                return_value=0,
            ) as execute,
        ):
            code = guard.main(
                [
                    "--stdin",
                    "--",
                    "governed-ios-pr-create",
                    "--expected-head-oid",
                    TARGET,
                    "--title",
                    self.title,
                ]
            )
        self.assertEqual(0, code)
        execute.assert_called_once_with(
            ["--expected-head-oid", TARGET, "--title", self.title],
            self.body,
        )


class FakeIOSPRBodyUpdateAPI:
    def __init__(self) -> None:
        self.head_oid = TARGET
        self.post_mutation_head_oid: str | None = None
        self.head_type = "commit"
        self.head_ref = f"refs/heads/{guard.IOS_PR_HEAD}"
        self.body = "Old governed body\n"
        self.state = "open"
        self.draft = True
        self.number: Any = guard.IOS_PR_NUMBER
        self.title = guard.IOS_PR_TITLE
        self.pr_head_ref = guard.IOS_PR_HEAD
        self.pr_head_oid = TARGET
        self.pr_head_repo = guard.RELEASE_GITHUB_REPO
        self.pr_base_ref = guard.IOS_PR_BASE
        self.pr_base_repo = guard.RELEASE_GITHUB_REPO
        self.readback_patch: dict[str, Any] | None = None
        self.mutations: list[tuple[str, str, dict[str, Any]]] = []

    def _assert_repo(self, endpoint: str) -> None:
        if not endpoint.startswith(f"repos/{guard.RELEASE_GITHUB_REPO}/"):
            raise AssertionError(f"un-pinned iOS PR endpoint: {endpoint}")

    def _pr(self) -> dict[str, Any]:
        value = {
            "number": self.number,
            "state": self.state,
            "draft": self.draft,
            "title": self.title,
            "body": self.body,
            "head": {
                "ref": self.pr_head_ref,
                "sha": self.pr_head_oid,
                "repo": {"full_name": self.pr_head_repo},
            },
            "base": {
                "ref": self.pr_base_ref,
                "repo": {"full_name": self.pr_base_repo},
            },
        }
        if self.mutations and self.readback_patch is not None:
            for key, replacement in self.readback_patch.items():
                if key == "head.repo.full_name":
                    value["head"]["repo"]["full_name"] = replacement
                elif key == "base.repo.full_name":
                    value["base"]["repo"]["full_name"] = replacement
                elif key.startswith("head."):
                    value["head"][key.removeprefix("head.")] = replacement
                elif key.startswith("base."):
                    value["base"][key.removeprefix("base.")] = replacement
                else:
                    value[key] = replacement
        return value

    def read(self, endpoint: str) -> Any:
        self._assert_repo(endpoint)
        if endpoint.endswith(f"/git/ref/heads/{guard.IOS_PR_HEAD}"):
            oid = (
                self.post_mutation_head_oid
                if self.mutations and self.post_mutation_head_oid is not None
                else self.head_oid
            )
            return {
                "ref": self.head_ref,
                "object": {"type": self.head_type, "sha": oid},
            }
        if endpoint.endswith(f"/pulls/{guard.IOS_PR_NUMBER}"):
            return copy.deepcopy(self._pr())
        raise AssertionError(f"unexpected iOS PR body read: {endpoint}")

    def mutate_json(
        self, method: str, endpoint: str, payload: Mapping[str, Any]
    ) -> Any:
        self._assert_repo(endpoint)
        stored = dict(payload)
        self.mutations.append((method, endpoint, stored))
        if (
            method != "PATCH"
            or endpoint
            != f"repos/{guard.RELEASE_GITHUB_REPO}/pulls/{guard.IOS_PR_NUMBER}"
            or set(stored) != {"body"}
        ):
            raise AssertionError(f"unexpected iOS PR body mutation: {method} {endpoint}")
        self.body = stored["body"]
        return self._pr()


class GovernedIOSPRBodyUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = FakeIOSPRBodyUpdateAPI()
        self.new_body = "New governed body\n"

    def arguments(self, api: FakeIOSPRBodyUpdateAPI | None = None) -> list[str]:
        source = api or self.api
        old_bytes = source.body.encode("utf-8")
        return [
            "--expected-head-oid",
            TARGET,
            "--expected-old-body-sha256",
            hashlib.sha256(old_bytes).hexdigest(),
            "--expected-old-body-size",
            str(len(old_bytes)),
        ]

    def execute(self) -> int:
        return guard.execute_governed_ios_pr_body_update(
            self.arguments(), self.new_body, api=self.api
        )

    def test_success_is_one_body_only_patch_with_exact_readback(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(0, self.execute())
        self.assertEqual(
            [
                (
                    "PATCH",
                    f"repos/{guard.RELEASE_GITHUB_REPO}/pulls/{guard.IOS_PR_NUMBER}",
                    {"body": self.new_body},
                )
            ],
            self.api.mutations,
        )
        receipt = json.loads(stdout.getvalue())
        self.assertEqual("governed-ios-pr-body-update", receipt["operation"])
        self.assertEqual(guard.IOS_PR_NUMBER, receipt["pr_number"])
        self.assertEqual(TARGET, receipt["head_oid"])
        self.assertEqual(
            hashlib.sha256(self.new_body.encode()).hexdigest(),
            receipt["body_sha256"],
        )

    def test_destination_identity_and_other_operations_are_not_in_grammar(self) -> None:
        for flag in (
            "--repo",
            "--host",
            "--dest",
            "--number",
            "--base",
            "--head",
            "--title",
            "--force",
            "--admin",
            "--ready",
            "--review",
            "--merge",
        ):
            with self.subTest(flag=flag), self.assertRaises(guard.UnsafeCommand):
                guard.execute_governed_ios_pr_body_update(
                    [*self.arguments(), flag, "attacker/value"],
                    self.new_body,
                    api=self.api,
                )
        self.assertEqual([], self.api.mutations)

    def test_argument_shape_and_payload_fail_closed_before_mutation(self) -> None:
        valid = self.arguments()
        cases = (
            [],
            valid[:-2],
            [*valid, "--expected-head-oid", TARGET],
            [*valid[:1], "a" * 39, *valid[2:]],
            [*valid[:3], "A" * 64, *valid[4:]],
            [*valid[:5], "0"],
            [*valid[:5], "01"],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(
                (guard.UnsafeCommand, guard.ReleaseGuardError)
            ):
                guard.execute_governed_ios_pr_body_update(
                    arguments, self.new_body, api=self.api
                )
        unsafe_mention = "unsafe " + chr(64) + "person body\n"
        for body in ("", unsafe_mention, self.api.body):
            with self.subTest(body=body), self.assertRaises(guard.ReleaseGuardError):
                guard.execute_governed_ios_pr_body_update(
                    self.arguments(), body, api=self.api
                )
        self.assertEqual([], self.api.mutations)

    def test_remote_ref_and_every_pr_precondition_are_load_bearing(self) -> None:
        mutations = (
            lambda api: setattr(api, "head_ref", "refs/heads/other"),
            lambda api: setattr(api, "head_type", "tag"),
            lambda api: setattr(api, "head_oid", WRONG),
            lambda api: setattr(api, "number", 17),
            lambda api: setattr(api, "state", "closed"),
            lambda api: setattr(api, "draft", False),
            lambda api: setattr(api, "title", "changed"),
            lambda api: setattr(api, "pr_head_ref", "other"),
            lambda api: setattr(api, "pr_head_oid", WRONG),
            lambda api: setattr(api, "pr_head_repo", "other/repo"),
            lambda api: setattr(api, "pr_base_ref", "other"),
            lambda api: setattr(api, "pr_base_repo", "other/repo"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.api = FakeIOSPRBodyUpdateAPI()
                arguments = self.arguments(self.api)
                mutate(self.api)
                with self.assertRaises(guard.ReleaseGuardError):
                    guard.execute_governed_ios_pr_body_update(
                        arguments, self.new_body, api=self.api
                    )
                self.assertEqual([], self.api.mutations)

    def test_old_body_hash_and_size_are_independent_preconditions(self) -> None:
        valid = self.arguments()
        cases = (
            [*valid[:3], "0" * 64, *valid[4:]],
            [*valid[:5], str(len(self.api.body.encode()) + 1)],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaisesRegex(
                guard.ReleaseGuardError, "old body bytes"
            ):
                guard.execute_governed_ios_pr_body_update(
                    arguments, self.new_body, api=self.api
                )
        self.assertEqual([], self.api.mutations)

    def test_post_mutation_ref_and_every_readback_field_are_red_after_one_patch(self) -> None:
        patches = (
            {"number": 17},
            {"state": "closed"},
            {"draft": False},
            {"title": "changed"},
            {"body": "changed\n"},
            {"head.ref": "other"},
            {"head.sha": WRONG},
            {"head.repo.full_name": "other/repo"},
            {"base.ref": "other"},
            {"base.repo.full_name": "other/repo"},
        )
        for patch in patches:
            with self.subTest(patch=patch):
                self.api = FakeIOSPRBodyUpdateAPI()
                self.api.readback_patch = patch
                with self.assertRaisesRegex(guard.ReleaseGuardError, "readback"):
                    self.execute()
                self.assertEqual(1, len(self.api.mutations))
        self.api = FakeIOSPRBodyUpdateAPI()
        self.api.post_mutation_head_oid = WRONG
        with self.assertRaisesRegex(guard.ReleaseGuardError, "remote branch"):
            self.execute()
        self.assertEqual(1, len(self.api.mutations))

    def test_reuse_cannot_create_a_second_mutation(self) -> None:
        arguments = self.arguments()
        self.assertEqual(
            0,
            guard.execute_governed_ios_pr_body_update(
                arguments, self.new_body, api=self.api
            ),
        )
        with self.assertRaises(guard.ReleaseGuardError):
            guard.execute_governed_ios_pr_body_update(
                arguments, "Third governed body\n", api=self.api
            )
        self.assertEqual(1, len(self.api.mutations))

    def test_main_routes_exact_validated_body_to_dedicated_adapter(self) -> None:
        arguments = self.arguments()
        stdin = mock.Mock()
        stdin.buffer.read.return_value = self.new_body.encode("utf-8")
        with (
            mock.patch.object(guard.sys, "stdin", stdin),
            mock.patch.object(
                guard,
                "execute_governed_ios_pr_body_update",
                return_value=0,
            ) as execute,
        ):
            code = guard.main(
                ["--stdin", "--", "governed-ios-pr-body-update", *arguments]
            )
        self.assertEqual(0, code)
        execute.assert_called_once_with(arguments, self.new_body)


class GitHubAPIIOSTargetBoundaryTests(unittest.TestCase):
    def test_pr_listing_uses_fixed_host_repo_and_overrides_inherited_destination(self) -> None:
        completed = mock.Mock(returncode=0, stdout=b"[[]]", stderr=b"")
        endpoint = (
            "repos/soyeht/soyeht-ios/pulls?state=all&"
            "head=soyeht%3Aci%2Fgoverned-macos-release&base=main&per_page=100"
        )
        with (
            mock.patch.dict(
                guard.os.environ,
                {"GH_HOST": "attacker.invalid", "GH_REPO": "attacker/repo"},
                clear=False,
            ),
            mock.patch.object(
                guard.subprocess, "run", return_value=completed
            ) as run,
        ):
            self.assertEqual([], guard.GitHubAPI().read_pages(endpoint))
        command = run.call_args.args[0]
        self.assertEqual("github.com", command[command.index("--hostname") + 1])
        self.assertEqual(endpoint, command[-1])
        environment = run.call_args.kwargs["env"]
        self.assertEqual("github.com", environment["GH_HOST"])
        self.assertEqual("soyeht/soyeht-ios", environment["GH_REPO"])


class GovernedReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = FakeReleaseAPI()
        execution_contract_digests = {
            path: hashlib.sha256(
                self.api.workflow
                if path == guard.RELEASE_WORKFLOW_FILE
                else self.api.execution_contract[path]
            ).hexdigest()
            for path in guard.RELEASE_EXECUTION_CONTRACT_SHA256
        }
        execution_contract_digest_patch = mock.patch.object(
            guard,
            "RELEASE_EXECUTION_CONTRACT_SHA256",
            execution_contract_digests,
        )
        execution_contract_digest_patch.start()
        self.addCleanup(execution_contract_digest_patch.stop)

    def common(self) -> list[str]:
        return [
            "--tag-ref",
            TAG_REF,
            "--version",
            VERSION,
            "--target-oid",
            TARGET,
            "--expected-main",
            MAIN,
        ]

    def execute(
        self,
        operation: str,
        payload: str = "",
        extra: list[str] | None = None,
    ) -> int:
        operation_extra = list(extra or [])
        if operation != "tag-object-create" and "--tag-object-oid" not in operation_extra:
            operation_extra = ["--tag-object-oid", TAG_OBJECT, *operation_extra]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = guard.execute_governed_release(
                [operation, *self.common(), *operation_extra],
                payload,
                api=self.api,
            )
        self.assertIn(f'"operation":"{operation}"', stdout.getvalue())
        return result

    def asset_file(self, payload: bytes) -> tuple[str, str, str]:
        temporary = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        with temporary:
            temporary.write(payload)
        return (
            temporary.name,
            str(len(payload)),
            hashlib.sha256(payload).hexdigest(),
        )

    def test_tag_object_create_has_one_mutation_and_exact_readback(self) -> None:
        self.assertEqual(0, self.execute("tag-object-create", TAG_MESSAGE))
        self.assertEqual([("POST", f"repos/{guard.RELEASE_GITHUB_REPO}/git/tags")], self.api.mutations)
        self.assertNotIn(TAG, self.api.tags)

    def test_tag_object_readback_mismatch_is_red_after_one_mutation(self) -> None:
        self.api.tag_object_readback_override = {
            "sha": TAG_OBJECT,
            "tag": TAG,
            "message": TAG_MESSAGE,
            "object": {"type": "commit", "sha": WRONG},
        }
        with self.assertRaises(guard.ReleaseGuardError):
            guard.execute_governed_release(
                ["tag-object-create", *self.common()], TAG_MESSAGE, api=self.api
            )
        self.assertEqual(1, len(self.api.mutations))

    def test_linewrapped_contents_api_base64_is_decoded_strictly(self) -> None:
        self.api.linewrap_contents = True
        self.assertEqual(0, self.execute("tag-object-create", TAG_MESSAGE))
        self.assertEqual(1, len(self.api.mutations))

    def test_tag_ref_create_has_one_mutation_and_peels_to_commit(self) -> None:
        self.api.tag_objects[TAG_OBJECT] = {
            "sha": TAG_OBJECT,
            "tag": TAG,
            "message": TAG_MESSAGE,
            "object": {"type": "commit", "sha": TARGET},
        }
        self.assertEqual(
            0,
            self.execute(
                "tag-ref-create",
                TAG_MESSAGE,
                extra=["--tag-object-oid", TAG_OBJECT],
            ),
        )
        self.assertEqual(1, len(self.api.mutations))
        self.assertEqual(TAG_OBJECT, self.api.tags[TAG])

    def test_tag_ref_readback_mismatch_is_red_after_one_mutation(self) -> None:
        self.api.tag_objects[TAG_OBJECT] = {
            "sha": TAG_OBJECT,
            "tag": TAG,
            "message": TAG_MESSAGE,
            "object": {"type": "commit", "sha": TARGET},
        }
        self.api.tag_ref_readback_override = {
            "ref": TAG_REF,
            "object": {"type": "tag", "sha": WRONG},
        }
        with self.assertRaises(guard.ReleaseGuardError):
            guard.execute_governed_release(
                [
                    "tag-ref-create",
                    *self.common(),
                    "--tag-object-oid",
                    TAG_OBJECT,
                ],
                TAG_MESSAGE,
                api=self.api,
            )
        self.assertEqual(1, len(self.api.mutations))

    def test_tag_ref_rejects_a_different_or_missing_message_before_mutation(self) -> None:
        self.api.tag_objects[TAG_OBJECT] = {
            "sha": TAG_OBJECT,
            "tag": TAG,
            "message": "original guarded message\n",
            "object": {"type": "commit", "sha": TARGET},
        }
        for payload in ("", "different message\n"):
            with self.subTest(payload=payload):
                self.assert_blocked_before_mutation(
                    "tag-ref-create",
                    payload=payload,
                    extra=["--tag-object-oid", TAG_OBJECT],
                )

    def test_release_draft_create_has_one_mutation_and_no_assets(self) -> None:
        self.api.add_tag()
        self.assertEqual(
            0,
            self.execute(
                "release-draft-create",
                "Release body\n",
                ["--title", f"Soyeht macOS {VERSION}"],
            ),
        )
        self.assertEqual(1, len(self.api.mutations))
        release = next(iter(self.api.releases.values()))
        self.assertIs(True, release["draft"])
        self.assertEqual([], release["assets"])

    def test_release_draft_readback_mismatch_is_red_after_one_mutation(self) -> None:
        self.api.add_tag()
        self.api.release_readback_patch = {"body": "different body\n"}
        with self.assertRaises(guard.ReleaseGuardError):
            guard.execute_governed_release(
                [
                    "release-draft-create",
                    *self.common(),
                    "--tag-object-oid",
                    TAG_OBJECT,
                    "--title",
                    f"Soyeht macOS {VERSION}",
                ],
                "Release body\n",
                api=self.api,
            )
        self.assertEqual(1, len(self.api.mutations))

    def test_asset_upload_has_one_mutation_and_digest_readback(self) -> None:
        self.api.add_tag()
        release_id = self.api.add_release()
        asset_path, size, digest = self.asset_file(b"signed dmg bytes")
        self.assertEqual(
            0,
            self.execute(
                "asset-upload",
                extra=[
                    "--release-id",
                    str(release_id),
                    "--asset-name",
                    "Soyeht.dmg",
                    "--asset-path",
                    asset_path,
                    "--asset-size",
                    size,
                    "--asset-sha256",
                    digest,
                ],
            ),
        )
        self.assertEqual(1, len(self.api.mutations))

    def test_release_publish_has_one_mutation_and_exact_asset_set(self) -> None:
        self.api.add_tag()
        release_id = self.api.add_release()
        dmg = b"dmg"
        appcast = b"xml"
        self.api.add_asset(release_id, "Soyeht.dmg", dmg)
        self.api.add_asset(release_id, "appcast.xml", appcast)
        specs = [
            f"Soyeht.dmg:{len(dmg)}:{hashlib.sha256(dmg).hexdigest()}",
            f"appcast.xml:{len(appcast)}:{hashlib.sha256(appcast).hexdigest()}",
        ]
        self.assertEqual(
            0,
            self.execute(
                "release-publish",
                extra=[
                    "--release-id",
                    str(release_id),
                    "--asset",
                    specs[0],
                    "--asset",
                    specs[1],
                ],
            ),
        )
        self.assertEqual(1, len(self.api.mutations))
        self.assertIs(False, self.api.releases[release_id]["draft"])

    def test_release_publish_readback_mismatch_is_red_after_one_mutation(self) -> None:
        self.api.add_tag()
        release_id = self.api.add_release()
        dmg = self.api.add_asset(release_id, "Soyeht.dmg", b"dmg")
        appcast = self.api.add_asset(release_id, "appcast.xml", b"xml")
        self.api.release_readback_patch = {"prerelease": True}
        with self.assertRaises(guard.ReleaseGuardError):
            guard.execute_governed_release(
                [
                    "release-publish",
                    *self.common(),
                    "--tag-object-oid",
                    TAG_OBJECT,
                    "--release-id",
                    str(release_id),
                    "--asset",
                    f"Soyeht.dmg:{dmg['size']}:{str(dmg['digest']).removeprefix('sha256:')}",
                    "--asset",
                    f"appcast.xml:{appcast['size']}:{str(appcast['digest']).removeprefix('sha256:')}",
                ],
                "",
                api=self.api,
            )
        self.assertEqual(1, len(self.api.mutations))

    def assert_blocked_before_mutation(
        self,
        operation: str,
        *,
        payload: str = "",
        extra: list[str] | None = None,
        error: type[Exception] = guard.ReleaseGuardError,
    ) -> None:
        operation_extra = list(extra or [])
        if operation != "tag-object-create" and "--tag-object-oid" not in operation_extra:
            operation_extra = ["--tag-object-oid", TAG_OBJECT, *operation_extra]
        with self.assertRaises(error):
            guard.execute_governed_release(
                [operation, *self.common(), *operation_extra],
                payload,
                api=self.api,
            )
        self.assertEqual([], self.api.mutations)


    def test_consumer_contract_absence_and_bypass_tokens_are_red(self) -> None:
        cases = (
            b"      expected_ref:\n      expected_oid:\n  contents: read",
            self.api.workflow.replace(
                guard.RELEASE_REQUIRED_BUILD_MARKER,
                b"# required-build marker removed",
            ),
            self.api.workflow.replace(
                b"        uses: actions/upload-artifact@v4",
                b"        # uses: actions/upload-artifact@v4",
            ),
            self.api.workflow + b"\ngh release create mac-v0.1.19",
            self.api.workflow + b"\n--clobber",
            self.api.workflow + b"\ngit tag mac-v0.1.19",
            self.api.workflow + b"\ngit push origin refs/tags/mac-v0.1.19",
            self.api.workflow + b"\n# unreviewed workflow byte",
        )
        for workflow in cases:
            with self.subTest(workflow=workflow):
                self.api = FakeReleaseAPI()
                self.api.workflow = workflow
                self.assert_blocked_before_mutation(
                    "tag-object-create", payload=TAG_MESSAGE
                )

    def test_each_execution_contract_blob_drift_is_red_before_mutation(self) -> None:
        for path in guard.RELEASE_EXECUTION_CONTRACT_SHA256:
            with self.subTest(path=path):
                self.api = FakeReleaseAPI()
                if path == guard.RELEASE_WORKFLOW_FILE:
                    self.api.workflow += b"\n# drift"
                else:
                    self.api.execution_contract[path] += b"# drift\n"
                self.assert_blocked_before_mutation(
                    "tag-object-create", payload=TAG_MESSAGE
                )

    def test_tag_shorthand_version_mismatch_and_destination_flags_are_red(self) -> None:
        malformed = self.common()
        malformed[1] = TAG
        with self.assertRaises(guard.ReleaseGuardError):
            guard.execute_governed_release(
                ["tag-object-create", *malformed], TAG_MESSAGE, api=self.api
            )
        for forbidden in ("--repo", "--host", "--dest", "--force", "--admin", "--clobber"):
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(guard.UnsafeCommand):
                    guard.execute_governed_release(
                        ["tag-object-create", *self.common(), forbidden, "x"],
                        TAG_MESSAGE,
                        api=self.api,
                    )
        self.api.project = b"MARKETING_VERSION = 9.9.9;"
        self.assert_blocked_before_mutation("tag-object-create", payload=TAG_MESSAGE)

    def test_main_drift_nonancestor_branch_ambiguity_and_reuse_are_red(self) -> None:
        mutators = (
            lambda api: setattr(api, "main_oid", WRONG),
            lambda api: setattr(api, "compare_status", "diverged"),
            lambda api: setattr(api, "merge_base", WRONG),
            lambda api: setattr(api, "branch_exists", True),
            lambda api: api.add_tag(),
            lambda api: api.add_release(),
        )
        for mutate in mutators:
            with self.subTest(mutate=mutate):
                self.api = FakeReleaseAPI()
                mutate(self.api)
                self.assert_blocked_before_mutation(
                    "tag-object-create", payload=TAG_MESSAGE
                )

    def test_lightweight_tag_and_wrong_tag_target_are_red(self) -> None:
        self.api.add_tag(object_type="commit")
        release_id = self.api.add_release()
        self.assert_blocked_before_mutation(
            "asset-upload",
            extra=[
                "--release-id",
                str(release_id),
                "--asset-name",
                "Soyeht.dmg",
                "--asset-path",
                "/nonexistent",
                "--asset-size",
                "1",
                "--asset-sha256",
                "0" * 64,
            ],
        )
        self.api = FakeReleaseAPI()
        self.api.add_tag(target=WRONG)
        release_id = self.api.add_release()
        self.assert_blocked_before_mutation(
            "release-publish",
            extra=[
                "--release-id",
                str(release_id),
                "--asset",
                f"Soyeht.dmg:1:{'0' * 64}",
                "--asset",
                f"appcast.xml:1:{'1' * 64}",
            ],
        )

    def test_asset_path_digest_size_reuse_and_readback_mismatch_are_red(self) -> None:
        self.api.add_tag()
        release_id = self.api.add_release()
        asset_path, size, digest = self.asset_file(b"payload")
        base_extra = [
            "--release-id",
            str(release_id),
            "--asset-name",
            "Soyeht.dmg",
            "--asset-path",
            asset_path,
            "--asset-size",
            size,
            "--asset-sha256",
            digest,
        ]
        for index, replacement in ((7, "0" * 64), (5, str(int(size) + 1))):
            with self.subTest(replacement=replacement):
                changed = list(base_extra)
                changed[index] = replacement
                self.assert_blocked_before_mutation("asset-upload", extra=changed)
        self.api.add_asset(release_id, "Soyeht.dmg", b"existing")
        self.assert_blocked_before_mutation("asset-upload", extra=base_extra)

        self.api = FakeReleaseAPI()
        self.api.add_tag()
        release_id = self.api.add_release()
        self.api.asset_readback_override = {
            "id": 91,
            "name": "Soyeht.dmg",
            "size": len(b"payload"),
            "digest": f"sha256:{'f' * 64}",
            "state": "uploaded",
        }
        with self.assertRaises(guard.ReleaseGuardError):
            guard.execute_governed_release(
                [
                    "asset-upload",
                    *self.common(),
                    "--tag-object-oid",
                    TAG_OBJECT,
                    "--release-id",
                    str(release_id),
                    "--asset-name",
                    "Soyeht.dmg",
                    "--asset-path",
                    asset_path,
                    "--asset-size",
                    size,
                    "--asset-sha256",
                    digest,
                ],
                "",
                api=self.api,
            )
        self.assertEqual(1, len(self.api.mutations))

    def test_asset_symlink_is_red_before_upload(self) -> None:
        self.api.add_tag()
        release_id = self.api.add_release()
        asset_path, size, digest = self.asset_file(b"payload")
        link_path = Path(asset_path).with_name(Path(asset_path).name + "-link")
        link_path.symlink_to(asset_path)
        self.addCleanup(link_path.unlink, missing_ok=True)
        self.assert_blocked_before_mutation(
            "asset-upload",
            extra=[
                "--release-id",
                str(release_id),
                "--asset-name",
                "Soyeht.dmg",
                "--asset-path",
                str(link_path),
                "--asset-size",
                size,
                "--asset-sha256",
                digest,
            ],
        )

    def test_publish_missing_extra_or_digestless_assets_are_red(self) -> None:
        self.api.add_tag()
        release_id = self.api.add_release()
        dmg = self.api.add_asset(release_id, "Soyeht.dmg", b"dmg")
        valid_dmg = f"Soyeht.dmg:{dmg['size']}:{str(dmg['digest']).removeprefix('sha256:')}"
        for second in (
            valid_dmg,
            f"appcast.xml:3:{'0' * 64}",
        ):
            with self.subTest(second=second):
                self.assert_blocked_before_mutation(
                    "release-publish",
                    extra=[
                        "--release-id",
                        str(release_id),
                        "--asset",
                        valid_dmg,
                        "--asset",
                        second,
                    ],
                )
        self.api.releases[release_id]["assets"][0]["digest"] = None
        self.assert_blocked_before_mutation(
            "release-publish",
            extra=[
                "--release-id",
                str(release_id),
                "--asset",
                valid_dmg,
                "--asset",
                f"appcast.xml:3:{'0' * 64}",
            ],
        )

        self.api = FakeReleaseAPI()
        self.api.add_tag()
        release_id = self.api.add_release()
        dmg = self.api.add_asset(release_id, "Soyeht.dmg", b"dmg")
        appcast = self.api.add_asset(release_id, "appcast.xml", b"xml")
        self.api.add_asset(release_id, "unexpected.txt", b"extra")
        self.assert_blocked_before_mutation(
            "release-publish",
            extra=[
                "--release-id",
                str(release_id),
                "--asset",
                f"Soyeht.dmg:{dmg['size']}:{str(dmg['digest']).removeprefix('sha256:')}",
                "--asset",
                f"appcast.xml:{appcast['size']}:{str(appcast['digest']).removeprefix('sha256:')}",
            ],
        )

    def test_release_prerelease_mismatch_is_red(self) -> None:
        self.api.add_tag()
        release_id = self.api.add_release()
        self.api.releases[release_id]["prerelease"] = True
        self.assert_blocked_before_mutation(
            "release-publish",
            extra=[
                "--release-id",
                str(release_id),
                "--asset",
                f"Soyeht.dmg:1:{'0' * 64}",
                "--asset",
                f"appcast.xml:1:{'1' * 64}",
            ],
        )

    def test_nonempty_unused_payload_and_unknown_operation_are_red(self) -> None:
        self.api.add_tag()
        release_id = self.api.add_release()
        with self.assertRaises(guard.ReleaseGuardError):
            guard.execute_governed_release(
                [
                    "release-publish",
                    *self.common(),
                    "--tag-object-oid",
                    TAG_OBJECT,
                    "--release-id",
                    str(release_id),
                    "--asset",
                    f"Soyeht.dmg:1:{'0' * 64}",
                    "--asset",
                    f"appcast.xml:1:{'1' * 64}",
                ],
                "ignored prose",
                api=self.api,
            )
        with self.assertRaises(guard.UnsafeCommand):
            guard.execute_governed_release(
                ["release-delete", *self.common()], "", api=self.api
            )
        self.assertEqual([], self.api.mutations)


class GitHubAPIUploadBoundaryTests(unittest.TestCase):
    def test_upload_redirect_is_red_and_never_followed(self) -> None:
        release_id = 71
        upload_url = (
            f"https://uploads.github.com/repos/{guard.RELEASE_GITHUB_REPO}/"
            f"releases/{release_id}/assets{{?name,label}}"
        )
        token_result = mock.Mock(returncode=0, stdout=b"secret-token\n")
        response = mock.Mock(status=307, read=mock.Mock(return_value=b"redirect"))
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with (
            mock.patch.object(guard.subprocess, "run", return_value=token_result),
            mock.patch.object(
                guard.http.client, "HTTPSConnection", return_value=connection
            ) as connect,
            self.assertRaisesRegex(guard.ReleaseGuardError, "HTTP 307"),
        ):
            guard.GitHubAPI().upload_asset(
                release_id,
                "Soyeht.dmg",
                b"validated bytes",
                upload_url,
            )
        connect.assert_called_once_with("uploads.github.com", timeout=900)
        connection.request.assert_called_once()
        connection.close.assert_called_once_with()

    def test_upload_uses_exact_uploads_host_and_in_memory_validated_bytes(self) -> None:
        release_id = 71
        upload_url = (
            f"https://uploads.github.com/repos/{guard.RELEASE_GITHUB_REPO}/"
            f"releases/{release_id}/assets{{?name,label}}"
        )
        token_result = mock.Mock(returncode=0, stdout=b"secret-token\n")
        response = mock.Mock(
            status=201,
            read=mock.Mock(return_value=b'{"id":91,"name":"Soyeht.dmg"}'),
        )
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with (
            mock.patch.object(guard.subprocess, "run", return_value=token_result) as run,
            mock.patch.object(
                guard.http.client, "HTTPSConnection", return_value=connection
            ) as connect,
        ):
            result = guard.GitHubAPI().upload_asset(
                release_id,
                "Soyeht.dmg",
                b"validated bytes",
                upload_url,
            )
        self.assertEqual({"id": 91, "name": "Soyeht.dmg"}, result)
        run.assert_called_once_with(
            ["gh", "auth", "token", "--hostname", "github.com"],
            capture_output=True,
            check=False,
        )
        connect.assert_called_once_with("uploads.github.com", timeout=900)
        connection.request.assert_called_once_with(
            "POST",
            f"/repos/{guard.RELEASE_GITHUB_REPO}/releases/{release_id}/"
            "assets?name=Soyeht.dmg",
            body=b"validated bytes",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer secret-token",
                "Content-Type": "application/octet-stream",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        connection.close.assert_called_once_with()

    def test_upload_rejects_untrusted_upload_host_before_authentication(self) -> None:
        with (
            mock.patch.object(guard.subprocess, "run") as run,
            mock.patch.object(guard.http.client, "HTTPSConnection") as connect,
            self.assertRaises(guard.ReleaseGuardError),
        ):
            guard.GitHubAPI().upload_asset(
                71,
                "Soyeht.dmg",
                b"bytes",
                "https://example.invalid/repos/soyeht/soyeht-ios/releases/71/assets{?name,label}",
            )
        run.assert_not_called()
        connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
