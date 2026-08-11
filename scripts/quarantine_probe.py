#!/usr/bin/env python3
"""Run one quarantined Rust test repeatedly without turning flakes into a gate.

A test PASS or FAIL is an observation and leaves the probe successful.  A
vacant selector, build/toolchain error, or ambiguous Cargo transcript is an
invalid instrument and fails the probe job.  This distinction is load-bearing:
`cargo test` exits zero when `--exact` selects no tests.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence


RUNNING_RE = re.compile(r"^running (?P<count>\d+) tests?$", re.MULTILINE)
TEST_RESULT_RE = re.compile(
    r"^test (?P<name>\S+) \.\.\. (?P<status>ok|FAILED)$", re.MULTILINE
)


@dataclass(frozen=True)
class Observation:
    result: str
    selected: int
    reason: str = ""


@dataclass(frozen=True)
class ProbeConfig:
    issue: str
    attempts: int
    package: str
    test: str
    workspace: Path
    attempt_timeout_seconds: int = 30


def classify_cargo_output(output: str, returncode: int, expected_test: str) -> Observation:
    """Classify a Cargo transcript without treating return code zero as proof."""
    selected_counts = [int(match.group("count")) for match in RUNNING_RE.finditer(output)]
    result_lines = [
        (match.group("name"), match.group("status"))
        for match in TEST_RESULT_RE.finditer(output)
    ]

    if selected_counts != [1]:
        rendered = ",".join(str(count) for count in selected_counts) or "none"
        return Observation("INVALID", 0, f"selected-counts={rendered}")
    if len(result_lines) != 1 or result_lines[0][0] != expected_test:
        names = ",".join(name for name, _ in result_lines) or "none"
        return Observation("INVALID", 1, f"result-tests={names}")

    status = result_lines[0][1]
    if status == "ok" and returncode == 0:
        return Observation("PASS", 1)
    if status == "FAILED" and returncode != 0:
        return Observation("FAIL", 1)
    return Observation(
        "INVALID",
        1,
        f"status={status}-returncode={returncode}",
    )


Runner = Callable[..., subprocess.CompletedProcess[str]]


def _safe_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value) or "unknown"


def _emit(line: str, summary: Path | None) -> None:
    print(line, flush=True)
    if summary is not None:
        with summary.open("a", encoding="utf-8") as handle:
            handle.write(f"{line}\n")


def run_probe(
    config: ProbeConfig,
    *,
    runner: Runner = subprocess.run,
    summary: Path | None = None,
) -> int:
    command: Sequence[str] = (
        "cargo",
        "test",
        "--locked",
        "-p",
        config.package,
        "--lib",
        "--",
        "--ignored",
        "--exact",
        config.test,
        "--test-threads=1",
    )
    environment = os.environ.copy()
    environment["CARGO_TERM_COLOR"] = "never"
    runner_os = _safe_label(environment.get("RUNNER_OS", "local"))
    runner_job = _safe_label(environment.get("GITHUB_JOB", "local"))

    _emit(
        f"PROBE_COMMAND issue={config.issue} command={shlex.join(command)}",
        summary,
    )
    _emit(
        f"PROBE_NOTE issue={config.issue} attempts={config.attempts} "
        "cluster=single_job no_pooling=true clean_run_is_not_a_rate_claim=true",
        summary,
    )
    passes = failures = invalid = 0
    for attempt in range(1, config.attempts + 1):
        timed_out = False
        try:
            completed = runner(
                command,
                cwd=config.workspace,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                timeout=config.attempt_timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            timed_out = True
            captured = error.stdout or ""
            if isinstance(captured, bytes):
                captured = captured.decode(errors="replace")
            completed = subprocess.CompletedProcess(
                args=command,
                returncode=124,
                stdout=f"{captured}\nPROBE_TIMEOUT seconds={config.attempt_timeout_seconds}\n",
            )
        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
        observation = (
            Observation("INVALID", 0, "attempt-timeout")
            if timed_out
            else classify_cargo_output(completed.stdout, completed.returncode, config.test)
        )
        if observation.result == "PASS":
            passes += 1
        elif observation.result == "FAIL":
            failures += 1
        else:
            invalid += 1
        reason = f" reason={_safe_label(observation.reason)}" if observation.reason else ""
        _emit(
            f"PROBE_{config.issue} os={runner_os} job={runner_job} "
            f"attempt={attempt} selected={observation.selected} "
            f"result={observation.result} rc={completed.returncode}{reason}",
            summary,
        )

    _emit(
        f"PROBE_{config.issue} os={runner_os} job={runner_job} "
        f"attempts={config.attempts} passes={passes} failures={failures} invalid={invalid}",
        summary,
    )
    return 2 if invalid else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--issue", required=True)
    parser.add_argument("--attempts", required=True, type=int)
    parser.add_argument("--package", required=True)
    parser.add_argument("--test", required=True)
    parser.add_argument("--workspace", type=Path, default=Path("admin/rust"))
    parser.add_argument("--attempt-timeout-seconds", type=int, default=30)
    args = parser.parse_args()
    if args.attempts < 1:
        parser.error("--attempts must be positive")
    if not args.issue.isdigit():
        parser.error("--issue must contain digits only")
    if args.attempt_timeout_seconds < 1:
        parser.error("--attempt-timeout-seconds must be positive")
    return args


def main() -> int:
    args = parse_args()
    summary_value = os.environ.get("GITHUB_STEP_SUMMARY")
    return run_probe(
        ProbeConfig(
            issue=args.issue,
            attempts=args.attempts,
            package=args.package,
            test=args.test,
            workspace=args.workspace,
            attempt_timeout_seconds=args.attempt_timeout_seconds,
        ),
        summary=Path(summary_value) if summary_value else None,
    )


if __name__ == "__main__":
    raise SystemExit(main())
