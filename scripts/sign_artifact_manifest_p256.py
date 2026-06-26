#!/usr/bin/env python3
"""Sign theyos artifact-manifest payloads with an external P-256 key.

This is the signer command used by `imagebuilder sign-manifest`. It reads the
exact payload provided on stdin and signs those bytes as-is. The caller already
applies the artifact-manifest domain separator, so this wrapper must not prefix
or transform the input before signing.

The private key stays on the builder machine. This script only shells out to
OpenSSL, converts the DER ECDSA signature to raw r||s, and prints base64url
without padding on stdout.
"""

from __future__ import annotations

import argparse
import base64
import os
import shutil
import subprocess
import sys
from pathlib import Path


class SignatureFormatError(ValueError):
    """The OpenSSL DER signature was not a canonical P-256 ECDSA signature."""


def _read_der_length(der: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(der):
        raise SignatureFormatError("truncated DER length")
    first = der[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 2:
        raise SignatureFormatError("unsupported DER length form")
    if offset + count > len(der):
        raise SignatureFormatError("truncated DER long length")
    length = int.from_bytes(der[offset : offset + count], "big")
    offset += count
    if length < 0x80:
        raise SignatureFormatError("non-minimal DER length")
    return length, offset


def _read_der_integer(der: bytes, offset: int) -> tuple[bytes, int]:
    if offset >= len(der) or der[offset] != 0x02:
        raise SignatureFormatError("expected DER INTEGER")
    length, offset = _read_der_length(der, offset + 1)
    if length == 0:
        raise SignatureFormatError("empty DER INTEGER")
    end = offset + length
    if end > len(der):
        raise SignatureFormatError("truncated DER INTEGER")
    value = der[offset:end]
    if len(value) > 1 and value[0] == 0x00:
        value = value[1:]
    if len(value) > 32:
        raise SignatureFormatError("P-256 integer is wider than 32 bytes")
    return value.rjust(32, b"\x00"), end


def der_ecdsa_to_raw_p256(der: bytes) -> bytes:
    """Convert DER ECDSA-Sig-Value to P-256 raw r||s."""

    if not der or der[0] != 0x30:
        raise SignatureFormatError("expected DER SEQUENCE")
    sequence_length, offset = _read_der_length(der, 1)
    sequence_end = offset + sequence_length
    if sequence_end != len(der):
        raise SignatureFormatError("DER SEQUENCE length mismatch")
    r, offset = _read_der_integer(der, offset)
    s, offset = _read_der_integer(der, offset)
    if offset != sequence_end:
        raise SignatureFormatError("trailing bytes in DER signature")
    return r + s


def raw_p256_to_b64url(raw: bytes) -> str:
    if len(raw) != 64:
        raise SignatureFormatError("raw P-256 signature must be 64 bytes")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def sign_payload_with_openssl(payload: bytes, key_path: Path) -> bytes:
    openssl = shutil.which("openssl")
    if openssl is None:
        raise RuntimeError("openssl executable not found")
    if not key_path.is_file():
        raise RuntimeError("signing key file is not readable")

    result = subprocess.run(
        [openssl, "dgst", "-sha256", "-sign", str(key_path)],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("openssl signing failed")
    return result.stdout


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sign a theyos artifact-manifest payload with P-256/SHA-256"
    )
    parser.add_argument(
        "--key",
        default=os.environ.get("THEYOS_ARTIFACT_SIGNING_KEY", ""),
        help="path to the P-256 private key, or THEYOS_ARTIFACT_SIGNING_KEY",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if not args.key:
        print(
            "signing key is required via --key or THEYOS_ARTIFACT_SIGNING_KEY",
            file=sys.stderr,
        )
        return 2

    payload = sys.stdin.buffer.read()
    try:
        der_signature = sign_payload_with_openssl(payload, Path(args.key))
        raw_signature = der_ecdsa_to_raw_p256(der_signature)
        print(raw_p256_to_b64url(raw_signature))
    except Exception as exc:
        print(f"artifact manifest signing failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
