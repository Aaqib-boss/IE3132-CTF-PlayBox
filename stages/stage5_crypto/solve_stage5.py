#!/usr/bin/env python3
"""
solve_stage5.py - intended-path solver for Stage 5 (Cryptography). Pure stdlib.

    python solve_stage5.py [path/to/evidence.enc]        (default: build/evidence.enc)

Mirrors the manual workflow:
  1. Notice the file is not text and not a known container -> repeating-key XOR
  2. Guess the key length  (normalised Hamming distance, ALL pairs of blocks)
  3. Split into columns, break each column as a single-byte XOR (letter frequency)
  4. Decrypt, read the handler log, take the CASE{...} reference code

Lesson from building it: comparing only ADJACENT blocks guessed 14 (a multiple of 7)
on this short ciphertext; comparing all pairs is far more robust.
"""
import re
import sys
from itertools import combinations


def hamming_distance(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_key_length(ciphertext: bytes, max_len: int = 15) -> int:
    scores = {}
    for keysize in range(2, max_len + 1):
        chunks = [ciphertext[i:i + keysize] for i in range(0, len(ciphertext) - keysize, keysize)]
        if len(chunks) < 4:
            continue
        pairs = list(combinations(chunks, 2))
        distances = [hamming_distance(a, b) / keysize for a, b in pairs]
        scores[keysize] = sum(distances) / len(distances)
    return min(scores, key=scores.get)


def break_single_byte_xor(block: bytes) -> int:
    best_byte, best_score = 0, -1
    freq = "etaoin shrdlu"
    for key_byte in range(256):
        decoded = bytes(b ^ key_byte for b in block)
        score = sum(decoded.lower().count(c.encode()) for c in freq)
        if score > best_score:
            best_score, best_byte = score, key_byte
    return best_byte


def recover_key(ciphertext: bytes, keysize: int) -> bytes:
    return bytes(break_single_byte_xor(ciphertext[i::keysize]) for i in range(keysize))


def main(path: str = "build/evidence.enc") -> str:
    ciphertext = open(path, "rb").read()
    print(f"[1] {path}: {len(ciphertext)} bytes, first bytes {ciphertext[:8].hex()} (not text, not a container)")
    keysize = guess_key_length(ciphertext)
    print(f"[2] guessed key length : {keysize}")
    key = recover_key(ciphertext, keysize)
    print(f"[3] recovered key      : {key!r}")
    plaintext = bytes(b ^ key[i % len(key)] for i, b in enumerate(ciphertext))
    text = plaintext.decode(errors="replace")
    print("--- decrypted payload ---\n" + text.rstrip() + "\n-------------------------")
    m = re.search(r"CASE\{[^}]+\}", text)
    flag = m.group(0) if m else None
    print(f"[4] FLAG               : {flag}")
    return flag


if __name__ == "__main__":
    main(*sys.argv[1:2])
