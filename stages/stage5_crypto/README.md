# Stage 5 - Cryptography ("The Flaw in the Lock")  |  Owner: Shaheen
Difficulty: Medium  |  Delivery: no attachment (file comes from Stage 4)  |  Fully offline  |  No live service

## Story
The archive recovered from Subject C's device held one more file, encrypted with a home-made scheme.
Breaking it yields the handler log and the next target.

## What the player gets
Nothing new. The player's input is `evidence.enc` (415 bytes), recovered in Stage 4 from the hidden zip.
It is deliberately NOT attached to this challenge in CTFd, otherwise Stage 4 could be skipped.

## Intended solve
1. `evidence.enc` is not text and not a known container: repeating-key XOR.
2. Key length: normalised Hamming distance between ALL pairs of blocks -> 7.
3. Split into 7 columns and break each as a single-byte XOR with letter frequencies -> key `ledger7`.
4. Decrypt (CyberChef "XOR", or `solve_stage5.py`). The handler log contains the flag and the next target.

Flag: `CASE{ledger_xor_cracked}`

## What the solve gives the player (Stage 5 -> 6)
The decrypted log ends with:
```
NEXT TARGET: Internal File Converter
URL: http://10.10.10.100:8080/
Access: HTTP via web browser, no credentials required
```
This is the Stage 6 entry point. If the Stage 6 address changes, rebuild with `build/encrypt.py` (edit `build/evidence.txt` first) and re-run the Stage 4 build.

## Why there are no shortcuts (Requirement 7)
- The Stage 5 flag exists only inside the ciphertext, and the key never appears in any player file.
  `check_no_leak.py build/evidence.enc ...` scans for the flags and key in plain, UTF-16, base64, hex, rot13, reversed,
  any `CASE{` prefix, and every single-byte XOR: **PASS** (`solution/leak-stage5.txt`).
- The Stage 4 image was scanned for the Stage 5 flag and key as well (see Stage 4): **PASS**.
- The Stage 4 flag is a different string and sits in a different file, so a Stage 4 player never sees the Stage 5 flag.
- The RSA alternate path was dropped so CTFd has one canonical answer (files kept under `solution/unused-rsa/`, not player files).

## Build / test
```powershell
cd stages\stage5_crypto
python solve_stage5.py build\evidence.enc
python check_no_leak.py build\evidence.enc "CASE{ledger_xor_cracked}" "CASE{h1dden_str3am_ledger_4472}" ledger7
```
Standard library only. To rebuild the ciphertext: `cd build; python encrypt.py` (reads `evidence.txt`, key `ledger7`,
writes `evidence.enc`). Then rebuild the Stage 4 payload zip and image so they carry the new file.

`build\evidence.enc`: 415 bytes, SHA-256 `bb51b35ecd96e7d9ee2938a0246f89ac1c3222704a094823b73789f3e02fe8ef`.

## Reset / recovery
Static stage: nothing to reset.

## Files
| File | Purpose |
|---|---|
| `build/evidence.txt`, `build/encrypt.py`, `build/evidence.enc` | Plaintext, encryptor, ciphertext (not player files) |
| `solve_stage5.py` | Intended-path solver (use in video) |
| `check_no_leak.py` | Shortcut scanner |
| `hints.md`, `challenges_block.yml` | CTFd hints + block |
| `solution/` | leak scan result, unused RSA path (not player files) |
