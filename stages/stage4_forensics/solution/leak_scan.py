#!/usr/bin/env python3
"""leak_scan.py - look for flags in player-facing files, in many encodings.

Usage:
  python leak_scan.py --needle "CASE{flag_one}" --needle ledger7 PATH [PATH ...]
  python leak_scan.py --needle "CASE{x}" --strings strings-out.txt image.img

PATH can be a file or a folder. .zip files are scanned as-is AND member by
member (encrypted members are skipped and reported). Needles of the form
CASE{inner} are also searched as the bare inner keyword. Every needle is
checked as: plain, UTF-16LE/BE, base64 (3 alignments, UTF-8 and UTF-16LE),
hex (lower/upper), rot13, reversed. Any CASE{...} string in plain or UTF-16
is reported too. Exit code 1 if anything is found.
"""
import argparse, base64, codecs, hashlib, re, sys, zipfile
from pathlib import Path

def variants(text):
    raw8 = text.encode()
    raw16 = text.encode("utf-16-le")
    out = {
        "plain": raw8,
        "utf16le": raw16,
        "utf16be": text.encode("utf-16-be"),
        "rot13": codecs.encode(text, "rot13").encode(),
        "hex-lower": raw8.hex().encode(),
        "hex-upper": raw8.hex().upper().encode(),
        "reversed": raw8[::-1],
    }
    for name, data in (("utf8", raw8), ("utf16le", raw16)):
        for k in range(3):
            padded = b"\x00" * k + data
            enc = base64.b64encode(padded).decode().rstrip("=")
            enc = enc[(0, 2, 3)[k]:]          # drop chars that depend on the unknown preceding bytes
            if len(padded) % 3:
                enc = enc[:-1]                 # drop the partial last char
            if len(enc) >= 6:
                out[f"base64-{name}-shift{k}"] = enc.encode()
    return out

def build_needles(raw):
    needles = {}
    for text in raw + ["CASE{"]:
        needles[text] = variants(text)
        m = re.fullmatch(r"CASE\{(.+)\}", text)
        if m and len(m.group(1)) >= 6:
            needles[m.group(1) + "  (inner keyword)"] = variants(m.group(1))
    return needles

GENERIC = [
    ("CASE{...} plain", re.compile(rb"CASE\{[^}\x00]{1,80}\}", re.I)),
    ("CASE{...} utf16", re.compile(rb"(?:C\x00A\x00S\x00E\x00\{\x00)(?:[^}\x00]\x00){1,80}\}\x00", re.I)),
]
ASCII = re.compile(rb"[\x20-\x7e]{6,}")
UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")

def scan(label, data, needles):
    hits = []
    for needle, vs in needles.items():
        for enc, pat in vs.items():
            i = data.find(pat)
            if i != -1:
                hits.append(f"  HIT [{label}] needle={needle!r} form={enc} offset={i}")
    for name, rx in GENERIC:
        for m in rx.finditer(data):
            hits.append(f"  HIT [{label}] generic {name}: {m.group().decode('latin1')!r} offset={m.start()}")
    return hits

def zip_members(path):
    try:
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.flag_bits & 1:
                    yield info.filename, None
                else:
                    yield info.filename, z.read(info)
    except zipfile.BadZipFile:
        return

def dump_strings(out, label, data):
    out.write(f"\n===== {label} : ASCII =====\n")
    for m in ASCII.finditer(data):
        out.write(m.group().decode("ascii") + "\n")
    out.write(f"\n===== {label} : UTF-16LE =====\n")
    for m in UTF16.finditer(data):
        out.write(m.group().decode("utf-16-le") + "\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--needle", action="append", default=[], help="flag or secret to hunt for (repeatable)")
    ap.add_argument("--strings", help="also write strings (ASCII + UTF-16LE) of every scanned item to this file")
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args()

    needles = build_needles(a.needle)
    files = []
    for p in map(Path, a.paths):
        files += sorted(f for f in p.rglob("*") if f.is_file()) if p.is_dir() else [p]

    out = open(a.strings, "w", encoding="utf-8") if a.strings else None
    total = 0
    for f in files:
        data = f.read_bytes()
        print(f"\n{f}  ({len(data)} bytes)  SHA256={hashlib.sha256(data).hexdigest()}")
        items = [(str(f), data)]
        if f.suffix.lower() == ".zip":
            for name, content in zip_members(f):
                if content is None:
                    print(f"  note: member {name!r} is encrypted - skipped (expected for the ADS payload)")
                else:
                    items.append((f"{f.name}!{name}", content))
        for label, blob in items:
            hits = scan(label, blob, needles)
            total += len(hits)
            print("\n".join(hits) if hits else f"  clean: {label}")
            if out:
                dump_strings(out, label, blob)
    if out:
        out.close()
    print("\nRESULT:", "LEAKS FOUND (%d)" % total if total else "CLEAN - no flags/keys found in any scanned form")
    sys.exit(1 if total else 0)

if __name__ == "__main__":
    main()