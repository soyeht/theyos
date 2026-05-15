#!/usr/bin/env python3
"""
Generator for ../house_created_push.json.

Produces 5 deterministic (input, expected) pairs for the `house_created`
APNs push event contract (specs/005-soyeht-onboarding/contracts/push-events.md).

Derivation: SHA-256(SEED || domain || index_byte) → 32 bytes.
SHA-256 is chosen for cross-language reproducibility (identical output in Rust,
Python, Swift, Go, Java, …) without adding external RNG dependencies.

Run:
  uv run python admin/rust/server-rs/tests/fixtures/house_created_push/generate.py \
    > admin/rust/server-rs/tests/fixtures/house_created_push.json

Regenerate when the contract payload shape changes (push-events.md), or when
new fixture entries are needed. After regenerating, re-run the Rust test suite
(`cargo test -p server-rs house_created_push`) and the Swift
HouseCreatedPushPayloadTests to verify byte-equal output.
"""

import base64
import hashlib
import json
import sys

SEED = b"soyeht-onboarding-house-created-fixture-2026"
BASE_TS = 1_746_921_600  # 2025-05-11 00:00:00 UTC — entry i adds i*86400

HH_NAMES = [
    "Maple Home",
    "River Home",
    "Harbor Home",
    "Family Home",
    "Aurora Home",
]
LABELS = [
    "Developer Mac",
    "MacBook Pro",
    "Mac mini",
    'iMac 24"',
    "MacBook Air",
]


def derive(domain: str, index: int) -> bytes:
    """SHA-256(SEED || domain_utf8 || index_byte) → 32 bytes."""
    h = hashlib.sha256()
    h.update(SEED)
    h.update(domain.encode())
    h.update(bytes([index]))
    return h.digest()


def b32_lower_nopad(data: bytes) -> str:
    """RFC 4648 base32, lowercase, no padding — matches household-rs ids.rs."""
    return base64.b32encode(data).rstrip(b"=").decode().lower()


def make_entry(i: int) -> dict:
    hh_id_bytes = derive("hh_id", i)
    m_id_bytes = derive("m_id", i)
    anchor_bytes = derive("anchor", i)[:16]

    hh_id = "hh_" + b32_lower_nopad(hh_id_bytes)
    machine_id = "m_" + b32_lower_nopad(m_id_bytes)
    hh_name = HH_NAMES[i]
    machine_label = LABELS[i]
    anchor_hex = anchor_bytes.hex()
    pair_qr_uri = f"soyeht://pair?hh={hh_id}&anchor={anchor_hex}"
    ts = BASE_TS + i * 86_400

    return {
        "input": {
            "hh_id": hh_id,
            "hh_name": hh_name,
            "machine_id": machine_id,
            "machine_label": machine_label,
            "pair_qr_uri": pair_qr_uri,
            "ts": ts,
        },
        "expected": {
            "aps": {
                "alert": {
                    "title-loc-key": "house_created_title",
                    "loc-key": "house_created_body",
                    "loc-args": [hh_name],
                },
                "sound": "house-created.caf",
                "mutable-content": 1,
                "interruption-level": "active",
                "thread-id": "house-events",
            },
            "soyeht": {
                "v": 1,
                "type": "house_created",
                "hh_id": hh_id,
                "hh_name": hh_name,
                "machine_id": machine_id,
                "machine_label": machine_label,
                "pair_qr_uri": pair_qr_uri,
                "ts": ts,
            },
        },
    }


if __name__ == "__main__":
    entries = [make_entry(i) for i in range(5)]
    json.dump(entries, sys.stdout, indent=2, ensure_ascii=False)
    print()  # trailing newline
