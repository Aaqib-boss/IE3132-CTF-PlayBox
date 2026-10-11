#!/usr/bin/env python3
"""
solve_stage4.py - solver for Stage 4 (Forensics). Pure stdlib.

    python solve_stage4.py dist/subjectc-image.zip "CASE{...stage3 answer...}" [--out DIR]

The intended manual path is Autopsy / FTK Imager: open the image, browse
Users\\subjectc\\Documents, see that Resume.txt carries a second data stream
(Resume.txt:hidden.zip), extract it, open it with the Stage 3 flag as password.

This script automates the same result without a GUI. It does not parse NTFS; it
locates the stream's zip by its signatures (PK local header ... end-of-central-
directory record), which is enough because the stream is stored contiguously.
  1. read the raw image (from the player zip or a bare .img)
  2. carve every candidate zip that contains evidence.enc
  3. open it with the Stage 3 flag (ZipCrypto) as password; a wrong password fails
  4. print the recovery note (Stage 4 flag) and the SHA-256 of evidence.enc (Stage 5 input)
  --out DIR also writes evidence.enc and recovery_note.txt there.
"""
import hashlib
import io
import os
import re
import struct
import sys
import zipfile


def load_image(path: str) -> bytes:
    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            name = next(n for n in z.namelist() if n.lower().endswith((".img", ".raw", ".dd")))
            print(f"[1] {path}: member {name}")
            return z.read(name)
    print(f"[1] {path}")
    return open(path, "rb").read()


def carve_zips(data: bytes):
    """yield (offset, zip bytes) for every PK\\x03\\x04 .. PK\\x05\\x06 span that opens as a zip"""
    pos = 0
    while True:
        start = data.find(b"PK\x03\x04", pos)
        if start < 0:
            return
        pos = start + 4
        end = data.find(b"PK\x05\x06", start, start + 1_000_000)
        if end < 0:
            continue
        comment_len = struct.unpack("<H", data[end + 20:end + 22])[0]
        blob = data[start:end + 22 + comment_len]
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as z:
                z.namelist()
        except zipfile.BadZipFile:
            continue
        yield start, blob


def main(path, password, out=None):
    data = load_image(path)
    print(f"    {len(data)} bytes, NTFS signature at 0x10003: "
          f"{data[0x10003:0x1000b]!r}" if len(data) > 0x1000b else f"    {len(data)} bytes")
    found = [(o, b) for o, b in carve_zips(data) if b"evidence.enc" in b]
    assert found, "no hidden zip found in the image"
    offset, blob = found[0]
    print(f"[2] hidden zip carved at offset {offset} ({len(blob)} bytes), "
          f"members: {zipfile.ZipFile(io.BytesIO(blob)).namelist()}")
    z = zipfile.ZipFile(io.BytesIO(blob))
    try:
        z.read("evidence.enc", pwd=password.encode())
    except RuntimeError:
        print("[3] wrong password - the Stage 3 answer must be exact.")
        return None
    except zipfile.BadZipFile:
        print("[3] wrong password (CRC check failed) - the Stage 3 answer must be exact.")
        return None
    enc = z.read("evidence.enc", pwd=password.encode())
    note = z.read("recovery_note.txt", pwd=password.encode()).decode()
    print(f"[3] password accepted; evidence.enc = {len(enc)} bytes, "
          f"SHA-256 {hashlib.sha256(enc).hexdigest()}")
    print(f"[4] recovery note: {note.strip()}")
    flag = re.search(r"CASE\{[^}]+\}", note).group(0)
    print(f"[5] FLAG (Stage 4): {flag}")
    if out:
        os.makedirs(out, exist_ok=True)
        open(os.path.join(out, "evidence.enc"), "wb").write(enc)
        open(os.path.join(out, "recovery_note.txt"), "w").write(note)
        print(f"    wrote evidence.enc and recovery_note.txt to {out} (evidence.enc is the Stage 5 input)")
    return flag


if __name__ == "__main__":
    args = sys.argv[1:]
    out = None
    if "--out" in args:
        i = args.index("--out")
        out = args[i + 1]
        del args[i:i + 2]
    main(args[0] if args else "dist/subjectc-image.zip",
         args[1] if len(args) > 1 else "CASE{sh4dow_batch_idor_9103}", out)
