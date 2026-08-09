#!/usr/bin/env python3
"""An INDEPENDENT Noise responder, for proving our handshake against something
that is not ours.

The plan's M1 carried an interoperability test against the kernel's WireGuard,
and it existed for a reason the plan states better than anything else in it:
*two of your own programs agreeing prove nothing.*  We do not implement
WireGuard, so that specific test does not apply -- but the reason does, and a
real TUN round trip does not satisfy it either, because both ends are ours.

This is the replacement: a responder built on `noiseprotocol`, a pure-Python
implementation that shares no code, no state and no cryptography with Rust's
`snow`.  If our production endpoint completes the handshake with it and both
sides derive the SAME handshake hash, that is evidence about the protocol
rather than about our wiring.

Deliberately NOT a general-purpose tool.  It speaks exactly the parameters in
`mesh-session-core-rs/src/noise.rs` and refuses anything else:

    pattern    Noise_XX_25519_ChaChaPoly_BLAKE2s
    prologue   b"soyeht/mesh-session/v1" || 0x01     (domain and version only)
    framing    [4-byte big-endian length][message]
    flights    3, XX, payload empty and REQUIRED to be empty

Run standalone:

    uv run --with noiseprotocol python scripts/noise-conformance-peer.py <port>

It prints `LISTENING <port>` once bound -- callers must wait for that line
rather than sleeping, then `HANDSHAKE_HASH <hex>` after the third flight.
"""

from __future__ import annotations

import os
import socket
import struct
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

# Same ceiling the Rust wire layer enforces, so an oversized frame is refused
# here too rather than being absorbed by a peer that is more permissive than
# the implementation under test.
MAX_FRAME_LEN = 65535


def read_frame(conn: socket.socket) -> bytes:
    header = b""
    while len(header) < 4:
        chunk = conn.recv(4 - len(header))
        if not chunk:
            raise EOFError("peer closed during the length header")
        header += chunk
    (length,) = struct.unpack(">I", header)
    if length > MAX_FRAME_LEN:
        raise ValueError(f"frame length {length} exceeds the {MAX_FRAME_LEN} ceiling")
    body = b""
    while len(body) < length:
        chunk = conn.recv(length - len(body))
        if not chunk:
            raise EOFError("peer closed mid-frame")
        body += chunk
    return body


def write_frame(conn: socket.socket, payload: bytes) -> None:
    conn.sendall(struct.pack(">I", len(payload)) + payload)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: noise-conformance-peer.py <port>", file=sys.stderr)
        return 2
    port = int(sys.argv[1])

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    # The caller waits for this line. Sleeping instead would make the test
    # flaky on a loaded machine for a reason that has nothing to do with Noise.
    print(f"LISTENING {port}", flush=True)
    listener.settimeout(30)

    conn, _ = listener.accept()
    conn.settimeout(30)

    noise = NoiseConnection.from_name(PATTERN)
    noise.set_prologue(PROLOGUE)
    # XX authenticates both ends, so the responder needs a static key of its
    # own. Generated here and never shared with Rust: each side proves
    # possession of a key the other has never seen, which is the point of the
    # pattern and the reason this is not a fixed-vector test.
    noise.set_keypair_from_private_bytes(Keypair.STATIC, os.urandom(32))
    noise.set_as_responder()
    noise.start_handshake()

    # XX: <- e ; -> e, ee, s, es ; <- s, se
    first = noise.read_message(read_frame(conn))
    if first != b"":
        raise AssertionError(f"flight 1 must carry an empty payload, got {first!r}")
    write_frame(conn, noise.write_message())
    third = noise.read_message(read_frame(conn))
    if third != b"":
        raise AssertionError(f"flight 3 must carry an empty payload, got {third!r}")
    if not noise.handshake_finished:
        raise AssertionError("handshake did not finish after the three XX flights")

    print("HANDSHAKE_HASH " + noise.get_handshake_hash().hex(), flush=True)

    # Transport in both directions. A handshake that agrees but cannot carry a
    # record would be agreement about nothing.
    received = noise.decrypt(read_frame(conn))
    print("DECRYPTED " + received.decode("utf-8"), flush=True)
    write_frame(conn, noise.encrypt(b"pong-from-independent-implementation"))

    conn.close()
    listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
