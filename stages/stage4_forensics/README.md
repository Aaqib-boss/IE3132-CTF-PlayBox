# Stage 4 - Forensics ("What Wiping Doesn't Erase")  |  Owner: Shaheen
Difficulty: Medium  |  Delivery: static disk image via CTFd (423 KB zip)  |  Fully offline  |  No live service

## Story
Subject C's personal device was seized. Nothing was wiped, but one file was tucked out of sight
using a feature of NTFS that normal file listings do not show.

## What the player gets
Only `dist/subjectc-image.zip` (attached in CTFd, plus the story text from `challenges_block.yml`).
It contains `subjectc-raw.img`, a 256 MiB raw disk image with one NTFS volume (label `SUBJECTC`).
Tools: Autopsy or FTK Imager to open the image, 7-Zip (or Windows) for the zip.

## Intended solve
1. Unzip, optionally verify the hashes below, open `subjectc-raw.img` in Autopsy (Add Data Source -> Disk Image)
   or FTK Imager (Add Evidence Item -> Image File).
2. Browse `Users\subjectc\Documents`: `Attendance.txt`, `Old_notes.txt`, `Goat.txt` (decoys) and `Resume.txt`.
3. `Resume.txt` has a second data stream, `Resume.txt:hidden.zip` (~767 bytes, starts with `PK`). Extract it.
4. The zip is password-protected (ZipCrypto). **The password is the Stage 3 flag**, exactly as submitted:
   `CASE{sh4dow_batch_idor_9103}`.
5. Inside: `recovery_note.txt` (contains the **Stage 4 flag**) and `evidence.enc` (415 bytes, the **Stage 5 input**).

Flag: `CASE{h1dden_str3am_ledger_4472}`

## Chain
- Stage 3 -> 4: technical dependency. Without the exact Stage 3 flag the stream cannot be opened.
- Stage 4 -> 5: `evidence.enc` only exists inside the encrypted stream. Stage 5 has no separate attachment.
- Stage 4 flag and Stage 5 flag are different strings. The Stage 5 flag exists only inside the XOR ciphertext.

## Why there are no shortcuts (Requirement 7)
- `check_no_leak.py` scans the player zip and the image inside it for the Stage 3, 4, 5 flags and the
  Stage 5 XOR key in plain, UTF-16LE/BE, base64 (3 alignments), hex, rot13, reversed and any `CASE{`
  prefix: **PASS** (result in `solution/leak-stage4-final.txt`).
- `solution/stage4-strings.txt` is the `strings` output of the image (ASCII + UTF-16LE). The only relevant
  hits are file names (`Resume.txt`, `hidden.zip`, `evidence.enc`), which is expected: ZipCrypto leaves
  member names readable, the contents are encrypted.
- The image was built from a fresh 256 MiB volume (no OS install), so there is no leftover residue from
  earlier placeholder files.

## Build / test
```powershell
cd stages\stage4_forensics
python solve_stage4.py dist\subjectc-image.zip "CASE{sh4dow_batch_idor_9103}" --out C:\temp\s4out
python check_no_leak.py dist\subjectc-image.zip "CASE{h1dden_str3am_ledger_4472}" "CASE{ledger_xor_cracked}" "CASE{sh4dow_batch_idor_9103}" ledger7
```
Standard library only. `solve_stage4.py` carves the zip by its signatures (the intended manual path is Autopsy),
checks the password, prints the recovery note and the SHA-256 of `evidence.enc`
(expected `bb51b35ecd96e7d9ee2938a0246f89ac1c3222704a094823b73789f3e02fe8ef`).

Rebuild (as built, in this order):
1. `diskpart /s build\mk.txt` creates a 256 MiB fixed VHD, formats NTFS, mounts it as `R:` (`build\dt.txt` detaches it).
2. Create `Users\subjectc\Documents` with the decoy files and `Resume.txt`.
3. Write the payload into the stream from `cmd.exe`: `type build\stage4-payload.zip > "R:\Users\subjectc\Documents\Resume.txt:hidden.zip"`.
4. Detach the VHD and convert to raw (`VBoxManage clonemedium disk ... --format RAW`), then zip as `dist\subjectc-image.zip`.
5. `build\stage4-payload.zip` = `evidence.enc` (from Stage 5) + `build\recovery_note.txt`, built with
   `7z a -tzip -mem=ZipCrypto build\stage4-payload.zip <evidence.enc> build\recovery_note.txt -p<Stage 3 flag>`.

## Checksums
| File | SHA-256 |
|---|---|
| `dist/subjectc-image.zip` (432,603 bytes) | `5e88093afe0ec9468e08b452ee1dbd092fc3dbc986c2ae176805f451d57378d7` |
| `subjectc-raw.img` (268,435,456 bytes, inside the zip) | `3fd7565007675952321b7e59a201d001541ff6c100f64685ec3a80551d45f3c0` |

## Reset / recovery
Static stage: nothing to reset. The raw `.img` and `.vhd` are not committed (see `.gitignore`); only the 423 KB
player zip is. Regenerate by repeating the build steps above.

## Files
| File | Purpose |
|---|---|
| `dist/subjectc-image.zip` | **The only file players download** |
| `solve_stage4.py` | Intended-result solver (use in video) |
| `check_no_leak.py` | Shortcut scanner |
| `hints.md`, `challenges_block.yml` | CTFd hints + block |
| `build/` | diskpart scripts, recovery note and payload zip (not player files) |
| `solution/` | leak scan results, `strings` output, scan script (not player files) |
