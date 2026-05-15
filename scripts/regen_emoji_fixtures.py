# /// script
# dependencies = ["blake3"]
# ///
"""Regenerate emoji-security-code-fixtures.csv using BLAKE3-256.

Reads the existing fixtures CSV for (m_pub_hex, nonce_hex, hostname) inputs,
recomputes the emoji codes via BLAKE3 (the new canonical algorithm), and
writes the updated CSV back in place.
"""
import csv
import sys
from pathlib import Path

import blake3

SPECS = Path(__file__).parent.parent / "specs" / "005-soyeht-onboarding" / "contracts"
WORDLIST_PATH = SPECS / "emoji-security-code-wordlist.csv"
FIXTURES_PATH = SPECS / "emoji-security-code-fixtures.csv"


def load_wordlist(path: Path) -> list[str]:
    emojis = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#") or row[0] == "word_index":
                continue
            emojis.append(row[1])
    assert len(emojis) == 2048, f"Expected 2048 entries, got {len(emojis)}"
    return emojis


def extract_indices(digest: bytes) -> list[int]:
    b = digest
    i0 = (b[0] << 3) | (b[1] >> 5)
    i1 = ((b[1] & 0x1F) << 6) | (b[2] >> 2)
    i2 = ((b[2] & 0x03) << 9) | (b[3] << 1) | (b[4] >> 7)
    i3 = ((b[4] & 0x7F) << 4) | (b[5] >> 4)
    i4 = ((b[5] & 0x0F) << 7) | (b[6] >> 1)
    i5 = ((b[6] & 0x01) << 10) | (b[7] << 2) | (b[8] >> 6)
    return [i0 & 0x7FF, i1 & 0x7FF, i2 & 0x7FF, i3 & 0x7FF, i4 & 0x7FF, i5 & 0x7FF]


def derive_emoji(m_pub_hex: str, nonce_hex: str, hostname: str, wordlist: list[str]) -> list[str]:
    m_pub = bytes.fromhex(m_pub_hex)
    nonce = bytes.fromhex(nonce_hex)
    payload = m_pub + nonce + hostname.encode("utf-8")
    digest = blake3.blake3(payload).digest()
    indices = extract_indices(digest)
    return [wordlist[i] for i in indices]


def main() -> None:
    wordlist = load_wordlist(WORDLIST_PATH)

    rows = []
    with open(FIXTURES_PATH, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            if not row:
                continue
            m_pub_hex, nonce_hex, hostname = row[0], row[1], row[2]
            emojis = derive_emoji(m_pub_hex, nonce_hex, hostname, wordlist)
            rows.append([m_pub_hex, nonce_hex, hostname] + emojis)

    with open(FIXTURES_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)

    print(f"Regenerated {len(rows)} fixture rows with BLAKE3-256.", file=sys.stderr)


if __name__ == "__main__":
    main()
