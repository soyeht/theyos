#!/usr/bin/env python3
"""Tests for scripts/sign_artifact_manifest_p256.py."""

from __future__ import annotations

import base64
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("sign_artifact_manifest_p256.py")
SPEC = importlib.util.spec_from_file_location("sign_artifact_manifest_p256", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
signer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signer)


def der_integer(value: bytes) -> bytes:
    return b"\x02" + bytes([len(value)]) + value


def der_sequence(payload: bytes) -> bytes:
    return b"\x30" + bytes([len(payload)]) + payload


def raw_to_der_integer(value: bytes) -> bytes:
    value = value.lstrip(b"\x00") or b"\x00"
    if value[0] & 0x80:
        value = b"\x00" + value
    return der_integer(value)


def raw_to_der(raw: bytes) -> bytes:
    r = raw[:32]
    s = raw[32:]
    return der_sequence(raw_to_der_integer(r) + raw_to_der_integer(s))


class DerToRawTests(unittest.TestCase):
    def test_short_integers_are_left_padded_to_32_bytes(self) -> None:
        der = der_sequence(der_integer(b"\x01") + der_integer(b"\x02"))
        raw = signer.der_ecdsa_to_raw_p256(der)
        self.assertEqual(raw, (31 * b"\x00") + b"\x01" + (31 * b"\x00") + b"\x02")

    def test_sign_prefix_zero_is_stripped_and_high_bit_values_survive(self) -> None:
        r = b"\x00" + (32 * b"\xff")
        s = b"\x00" + b"\x80" + (31 * b"\x00")
        der = der_sequence(der_integer(r) + der_integer(s))
        raw = signer.der_ecdsa_to_raw_p256(der)
        self.assertEqual(raw[:32], 32 * b"\xff")
        self.assertEqual(raw[32:], b"\x80" + (31 * b"\x00"))

    def test_integer_wider_than_p256_is_rejected(self) -> None:
        too_wide = b"\x01" + (32 * b"\x00")
        der = der_sequence(der_integer(too_wide) + der_integer(b"\x01"))
        with self.assertRaises(signer.SignatureFormatError):
            signer.der_ecdsa_to_raw_p256(der)

    def test_base64url_has_no_padding(self) -> None:
        encoded = signer.raw_p256_to_b64url(bytes(range(64)))
        self.assertNotIn("=", encoded)
        self.assertEqual(base64.urlsafe_b64decode(encoded + "=="), bytes(range(64)))


class SignerIntegrationTests(unittest.TestCase):
    def test_script_signs_stdin_payload_as_raw_p256_signature(self) -> None:
        if shutil.which("openssl") is None:
            self.skipTest("openssl not available")

        payload = b"already-domain-separated-payload"
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            key = tmpdir / "artifact-signing.key"
            pub = tmpdir / "artifact-signing.pub.pem"
            sig_der = tmpdir / "signature.der"

            subprocess.run(
                ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            subprocess.run(
                ["openssl", "ec", "-in", str(key), "-pubout", "-out", str(pub)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--key", str(key)],
                input=payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            encoded = proc.stdout.decode("ascii").strip()
            self.assertNotIn("=", encoded)
            raw = base64.urlsafe_b64decode(encoded + "==")
            self.assertEqual(len(raw), 64)
            sig_der.write_bytes(raw_to_der(raw))

            subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-verify",
                    str(pub),
                    "-signature",
                    str(sig_der),
                ],
                input=payload,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )


if __name__ == "__main__":
    unittest.main()
