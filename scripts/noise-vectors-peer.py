#!/usr/bin/env python3
"""An INDEPENDENT verifier for the M1a(a) deterministic Noise vectors.

M1a's other half, `scripts/noise-conformance-peer.py`, proves the LIVE
handshake against something that is not ours. It cannot pin bytes: both ends
generate fresh keypairs, so every run is a different transcript by
construction, and the plan says the right answer to that is not to weaken the
core.

This is the deterministic half. Given FIXED test keys it derives the whole XX
transcript with `noiseprotocol` -- a pure-Python implementation sharing no
code, no state and no cryptography with Rust's `snow` -- and prints it. The
Rust side derives the same transcript with `snow` and compares byte for byte.
Agreement is then evidence about the protocol, not about our wiring; and
because the keys are fixed, the bytes are stable enough to freeze into a
versioned corpus.

The keys are FIXED and they are TEST keys. They arrive on stdin, from a Rust
test that holds them as constants. Nothing here can be reached from a
production build: this file is a script invoked by `cargo test`, and the
MESH-SESSION production crate never adds a fixed-key seam -- see the
prohibition in `docs/mesh-plan.md` and the guard test that mechanizes it.
This claim and that guard reach exactly `mesh-session-core-rs/src`; other
crates are outside both.

Speaks exactly the parameters in `mesh-session-core-rs/src/noise.rs` and
refuses anything else:

    pattern    Noise_XX_25519_ChaChaPoly_BLAKE2s
    prologue   b"soyeht/mesh-session/v1" || 0x01     (domain and version only)
    flights    3, XX, payload empty and REQUIRED to be empty

Run standalone (the Rust test does exactly this):

    uv run --with noiseprotocol==0.3.1 python scripts/noise-vectors-peer.py

The version is PINNED for the same reason the conformance peer pins it: in a
conformance claim the external implementation *is* part of the vector, and a
floating comparand changes the claim's subject with no diff in the repository.

PROTOCOL. Reads one line of stdin: four hex-encoded 32-byte X25519 private
keys, space separated, in this order:

    initiator_static initiator_ephemeral responder_static responder_ephemeral

Then prints, in order and one per line:

    PEER_VERSIONS noiseprotocol=<v> python=<v>
    FLIGHT1 <hex>          initiator -> responder  (e)
    FLIGHT2 <hex>          responder -> initiator  (e, ee, s, es)
    FLIGHT3 <hex>          initiator -> responder  (s, se)
    HANDSHAKE_HASH <hex>   both sides agree; 32 bytes, BLAKE2s
    RECORD_I2R <hex>       first transport record, initiator -> responder
    RECORD_R2I <hex>       first transport record, responder -> initiator
    VECTORS_OK

`VECTORS_OK` is a terminator, not decoration: without it a truncated run
(peer killed mid-transcript) would look like a short but well-formed answer.

NEGATIVES. With `--negative <kind>` it re-derives the transcript, applies one
corruption, and reports how THIS implementation refuses it -- so a negative is
proven against the independent implementation too, not only against ours:

    bitflip    flip one bit of flight 2's ciphertext
    replay     feed flight 1 again in place of flight 2
    reorder    feed flight 3 where flight 2 belongs
    prologue   respond under a different prologue

It prints `NEGATIVE <kind> REFUSED <category>` where category is one of
`decrypt`, `handshake`, or `other` -- a stable class, never the incidental
message text, which varies by version and is not the claim.
"""

from __future__ import annotations

import sys

try:
    from noise.connection import Keypair, NoiseConnection
except ImportError:  # pragma: no cover - the caller decides whether this is fatal
    print(
        "PEER_UNAVAILABLE noiseprotocol is not installed; run under "
        "`uv run --with noiseprotocol`",
        flush=True,
    )
    raise SystemExit(3)

PROLOGUE = b"soyeht/mesh-session/v1" + bytes([1])
PATTERN = b"Noise_XX_25519_ChaChaPoly_BLAKE2s"

# The plaintexts whose first transport records are pinned. Fixed, ASCII, and
# deliberately distinguishable per direction so a swapped pair of records is a
# mismatch rather than a coincidence.
RECORD_I2R_PLAINTEXT = b"m1a-i2r"
RECORD_R2I_PLAINTEXT = b"m1a-r2i"


def _versions() -> str:
    try:
        from importlib.metadata import version

        noise_version = version("noiseprotocol")
    except Exception:  # pragma: no cover - metadata missing is not a protocol fact
        noise_version = "unknown"
    py = ".".join(str(p) for p in sys.version_info[:3])
    return f"PEER_VERSIONS noiseprotocol={noise_version} python={py}"


def _build(role: str, static_key: bytes, ephemeral_key: bytes, prologue: bytes):
    """A handshake state with FIXED static and ephemeral keys.

    `noiseprotocol` exposes the fixed-ephemeral seam the same way `snow` does:
    as a testing-only setter on the connection, never on a production path.
    """
    conn = NoiseConnection.from_name(PATTERN)
    conn.set_prologue(prologue)
    conn.set_as_initiator() if role == "initiator" else conn.set_as_responder()
    conn.set_keypair_from_private_bytes(Keypair.STATIC, static_key)
    conn.set_keypair_from_private_bytes(Keypair.EPHEMERAL, ephemeral_key)
    conn.start_handshake()
    return conn


def _transcript(keys: list[bytes], prologue: bytes = PROLOGUE):
    """Drive the 3 XX flights with fixed keys; return the flights and both ends."""
    i_static, i_ephemeral, r_static, r_ephemeral = keys
    initiator = _build("initiator", i_static, i_ephemeral, prologue)
    responder = _build("responder", r_static, r_ephemeral, prologue)

    flight1 = initiator.write_message(b"")
    responder.read_message(flight1)
    flight2 = responder.write_message(b"")
    initiator.read_message(flight2)
    flight3 = initiator.write_message(b"")
    responder.read_message(flight3)
    return flight1, flight2, flight3, initiator, responder


def _category(exc: BaseException) -> str:
    """Map a refusal to a STABLE class, never the incidental message text."""
    name = type(exc).__name__
    if "Decrypt" in name or "Tag" in name or "Crypto" in name:
        return "decrypt"
    if "Noise" in name or "Handshake" in name or "State" in name:
        return "handshake"
    return "other"


def _emit_positive(keys: list[bytes]) -> None:
    flight1, flight2, flight3, initiator, responder = _transcript(keys)

    # Both sides must agree on the handshake hash; disagreement here is a
    # protocol fact, not a reporting detail, so it is checked before printing.
    i_hash = initiator.get_handshake_hash()
    r_hash = responder.get_handshake_hash()
    if i_hash != r_hash:
        print("PEER_ERROR the two ends derived different handshake hashes", flush=True)
        raise SystemExit(4)

    record_i2r = initiator.encrypt(RECORD_I2R_PLAINTEXT)
    record_r2i = responder.encrypt(RECORD_R2I_PLAINTEXT)

    print(f"FLIGHT1 {flight1.hex()}", flush=True)
    print(f"FLIGHT2 {flight2.hex()}", flush=True)
    print(f"FLIGHT3 {flight3.hex()}", flush=True)
    print(f"HANDSHAKE_HASH {i_hash.hex()}", flush=True)
    print(f"RECORD_I2R {record_i2r.hex()}", flush=True)
    print(f"RECORD_R2I {record_r2i.hex()}", flush=True)
    print("VECTORS_OK", flush=True)


def _emit_negative(keys: list[bytes], kind: str) -> None:
    i_static, i_ephemeral, r_static, r_ephemeral = keys

    if kind == "prologue":
        # A responder under a DIFFERENT prologue must make the handshake fail.
        #
        # It does NOT fail on flight 1, and that is the protocol, not a gap:
        # XX's first message is a bare ephemeral key with no authenticated
        # material, so a diverging prologue is still invisible there. It
        # becomes visible on flight 2, the first message carrying an AEAD tag
        # computed over a handshake hash the prologue was mixed into. So the
        # refusal is asserted where the protocol actually detects it --
        # measured: reading flight 1 under a mismatched prologue succeeds.
        initiator = _build("initiator", i_static, i_ephemeral, PROLOGUE)
        responder = _build("responder", r_static, r_ephemeral, PROLOGUE + b"!")
        flight1 = initiator.write_message(b"")
        responder.read_message(flight1)
        flight2 = responder.write_message(b"")
        try:
            initiator.read_message(flight2)
        except BaseException as exc:  # noqa: BLE001 - the class IS the assertion
            print(f"NEGATIVE prologue REFUSED {_category(exc)}", flush=True)
            return
        print("NEGATIVE prologue ACCEPTED", flush=True)
        raise SystemExit(5)

    # The remaining three corrupt an otherwise valid transcript.
    initiator = _build("initiator", i_static, i_ephemeral, PROLOGUE)
    responder = _build("responder", r_static, r_ephemeral, PROLOGUE)
    flight1 = initiator.write_message(b"")
    responder.read_message(flight1)
    flight2 = responder.write_message(b"")

    if kind == "bitflip":
        corrupted = bytearray(flight2)
        corrupted[-1] ^= 0x01  # inside the tag: an unforgeable-integrity flip
        try:
            initiator.read_message(bytes(corrupted))
        except BaseException as exc:  # noqa: BLE001
            print(f"NEGATIVE bitflip REFUSED {_category(exc)}", flush=True)
            return
        print("NEGATIVE bitflip ACCEPTED", flush=True)
        raise SystemExit(5)

    if kind == "reorder":
        # Flight 3 arrives where flight 2 belongs. The initiator has not yet
        # processed flight 2, so this is an out-of-order message, not a replay.
        initiator.read_message(flight2)
        flight3 = initiator.write_message(b"")
        fresh_initiator = _build("initiator", i_static, i_ephemeral, PROLOGUE)
        fresh_initiator.write_message(b"")
        try:
            fresh_initiator.read_message(flight3)
        except BaseException as exc:  # noqa: BLE001
            print(f"NEGATIVE reorder REFUSED {_category(exc)}", flush=True)
            return
        print("NEGATIVE reorder ACCEPTED", flush=True)
        raise SystemExit(5)

    if kind == "replay":
        # Flight 1 replayed in flight 2's position.
        try:
            initiator.read_message(flight1)
        except BaseException as exc:  # noqa: BLE001
            print(f"NEGATIVE replay REFUSED {_category(exc)}", flush=True)
            return
        print("NEGATIVE replay ACCEPTED", flush=True)
        raise SystemExit(5)

    print(f"PEER_ERROR unknown negative kind: {kind}", flush=True)
    raise SystemExit(2)


def main(argv: list[str]) -> int:
    print(_versions(), flush=True)

    negative = None
    if len(argv) >= 3 and argv[1] == "--negative":
        negative = argv[2]
    elif len(argv) != 1:
        print(f"PEER_ERROR usage: {argv[0]} [--negative <kind>]", flush=True)
        return 2

    line = sys.stdin.readline().strip()
    parts = line.split()
    if len(parts) != 4:
        print("PEER_ERROR expected 4 hex keys on stdin", flush=True)
        return 2
    try:
        keys = [bytes.fromhex(p) for p in parts]
    except ValueError:
        print("PEER_ERROR keys must be hex", flush=True)
        return 2
    if any(len(k) != 32 for k in keys):
        print("PEER_ERROR each key must be 32 bytes", flush=True)
        return 2

    if negative is None:
        _emit_positive(keys)
    else:
        _emit_negative(keys, negative)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
