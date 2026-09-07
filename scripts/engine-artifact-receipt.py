#!/usr/bin/env python3
"""Validate package identity without executing the candidate engine.

The receipt is integrity metadata, not an independent trust anchor. The pinned
tarball and the signed app authenticate it. Rebinding is only for the build's
controlled codesign step, after validating its input with this same checker.
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path


def image_uuid(path):
    with path.open("rb") as source:
        header = source.read(32)
        if len(header) != 32:
            raise ValueError("truncated Mach-O header")
        magic, cpu, _, kind, count, size, _, _ = struct.unpack("<8I", header)
        if magic != 0xFEEDFACF or cpu != 0x0100000C or kind != 2:
            raise ValueError("expected a thin arm64 Mach-O executable")
        if size > 1024 * 1024 or count > size // 8:
            raise ValueError("invalid Mach-O load command bounds")
        commands = source.read(size)
    if len(commands) != size:
        raise ValueError("truncated Mach-O load commands")
    offset = 0
    found = None
    for _ in range(count):
        if offset + 8 > size:
            raise ValueError("truncated Mach-O command")
        command, length = struct.unpack_from("<II", commands, offset)
        if length < 8 or length % 8 or offset + length > size:
            raise ValueError("invalid Mach-O command length")
        if command == 0x1B:
            if length != 24 or found is not None:
                raise ValueError("ambiguous Mach-O UUID")
            found = commands[offset + 8:offset + 24].hex()
        offset += length
    if offset != size or found is None:
        raise ValueError("missing UUID or inconsistent Mach-O commands")
    return found


def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def validate(executable, receipt_path, *, rebind=False):
    if receipt_path.stat().st_size > 16384:
        raise ValueError("oversized engine receipt")
    receipt = json.loads(receipt_path.read_text())
    artifact = receipt["artifact"]
    if (not isinstance(artifact["version"], str) or not artifact["version"]
            or not isinstance(artifact["git_sha"], str) or not artifact["git_sha"]
            or type(artifact["pty_supervisor_protocol"]) is not int
            or not 0 < artifact["pty_supervisor_protocol"] <= 65535
            or not re.fullmatch(r"[0-9a-f]{32}", artifact["image_uuid"])
            or not re.fullmatch(r"[0-9a-f]{64}", receipt["executable_sha256"])):
        raise ValueError("invalid engine receipt fields")
    if image_uuid(executable) != artifact["image_uuid"]:
        raise ValueError("engine receipt identifies another linked image")
    actual = digest(executable)
    if not rebind and actual != receipt["executable_sha256"]:
        raise ValueError("engine executable differs from receipt")
    receipt["executable_sha256"] = actual
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("receipt", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--after-codesign", type=Path, help="write the rebound receipt to this build output")
    modes.add_argument("--from-build-info", type=Path, help="producer-only metadata from the controlled source build")
    args = parser.parse_args()
    try:
        if args.from_build_info is not None:
            # This tool never obtains metadata by executing a candidate. The
            # producer supplies its verified build observation or attestation.
            record = {"artifact": json.loads(args.from_build_info.read_text()),
                      "executable_sha256": digest(args.executable)}
            args.receipt.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
        receipt = validate(args.executable, args.receipt, rebind=args.after_codesign is not None)
        if args.after_codesign is not None:
            args.after_codesign.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"error: incompatible engine package: {error}\n")


if __name__ == "__main__":
    main()
