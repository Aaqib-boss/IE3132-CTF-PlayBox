#!/usr/bin/env python3
"""
check_no_leak.py - Requirement 7 guard (Stage 4 / Stage 5). Pure stdlib.

Proves none of the given secrets (flags, keys, passwords) is visible in a player file,
and that no CASE{ prefix is present, in any of these forms:
    plain, UTF-16LE/BE, base64 (3 alignments, UTF-8 and UTF-16LE),
    hex (lower/upper), rot13, reversed.
A .zip is scanned as a whole AND every member inside it is scanned (so the image inside
the player zip is checked, not just the compressed bytes).
For files under 2 MB the lazy single-byte-XOR attack is also tried.

    Stage 4:  python check_no_leak.py dist/subjectc-image.zip \
                  "CASE{h1dden_str3am_ledger_4472}" "CASE{ledger_xor_cracked}" \
                  "CASE{sh4dow_batch_idor_9103}" ledger7
    Stage 5:  python check_no_leak.py build/evidence.enc \
                  "CASE{ledger_xor_cracked}" "CASE{h1dden_str3am_ledger_4472}" ledger7

Exit code 0 = PASS, 1 = at least one leak.
"""
import base64
import codecs
import sys
import zipfile

XOR_LIMIT = 2 * 1024 * 1024


def b64_variants(raw: bytes):
    """base64 of `raw` at the three possible 3-byte alignments, trimmed to the characters
    that do not depend on the neighbouring bytes."""
    out = []
    for k in range(3):
        enc = base64.b64encode(b"\x00" * k + raw).decode()
        enc = enc[(0, 2, 3)[k]:].rstrip("=")
        if (k + len(raw)) % 3:
            enc = enc[:-1]
        if len(enc) >= 6:
            out.append(enc.encode())
    return out


def variants(s: str):
    """-> (case-insensitive variants, case-sensitive variants), each {label: bytes}"""
    b = s.encode()
    ci = {
        "plain": b,
        "utf16le": s.encode("utf-16-le"),
        "utf16be": s.encode("utf-16-be"),
        "rot13": codecs.encode(s, "rot13").encode(),
        "reversed": b[::-1],
    }
    cs = {"hex-lower": b.hex().encode(), "hex-upper": b.hex().upper().encode()}
    for i, v in enumerate(b64_variants(b)):
        cs[f"base64-utf8-shift{i}"] = v
    for i, v in enumerate(b64_variants(s.encode("utf-16-le"))):
        cs[f"base64-utf16le-shift{i}"] = v
    return ci, cs


def scan(label: str, data: bytes, secrets) -> int:
    low = data.lower()
    bad = 0
    for s in secrets:
        ci, cs = variants(s)
        for enc, needle in ci.items():
            if needle.lower() in low:
                print(f"[LEAK] {label}: '{s}' visible as {enc}")
                bad += 1
        for enc, needle in cs.items():
            if needle in data:
                print(f"[LEAK] {label}: '{s}' visible as {enc}")
                bad += 1
    for enc, needle in (("plain", b"case{"), ("utf16le", "case{".encode("utf-16-le")),
                        ("utf16be", "case{".encode("utf-16-be"))):
        if needle in low:
            print(f"[LEAK] {label}: 'CASE{{' prefix present as {enc}")
            bad += 1
    if len(data) <= XOR_LIMIT:
        for k in range(1, 256):
            if b"CASE{" in bytes(x ^ k for x in data):
                print(f"[LEAK] {label}: single-byte XOR 0x{k:02x} reveals CASE{{")
                bad += 1
    else:
        print(f"[i] {label}: {len(data)} bytes, single-byte-XOR attack skipped (over 2 MB)")
    return bad


def main(path, *secrets):
    if not secrets:
        sys.exit("usage: check_no_leak.py FILE SECRET [SECRET ...]")
    data = open(path, "rb").read()
    bad = scan(path, data, secrets)
    scanned = len(data)
    if path.lower().endswith(".zip") and zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                try:
                    inner = z.read(name)
                except RuntimeError:  # encrypted member: its bytes are not readable anyway
                    print(f"[i] {path}!{name}: encrypted, skipped")
                    continue
                bad += scan(f"{path}!{name}", inner, secrets)
                scanned += len(inner)
    print(f"[+] scanned {scanned} bytes -> {'FAIL' if bad else 'PASS: no shortcut hits'}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main(*sys.argv[1:])
