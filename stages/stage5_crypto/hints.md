# Stage 5 hints (add in CTFd; costs follow the 0 / 10% / 20% rule of the 350-point value, Kosgollage sets the final numbers)

| # | Cost | Hint |
|---|------|------|
| 1 | 0 pts  | The file is not random. It is English text scrambled byte by byte with a short key that repeats over and over. |
| 2 | 35 pts | To find the key length, compare blocks of the ciphertext: the right length gives blocks that are closer to each other (Hamming distance / index of coincidence). Compare ALL pairs of blocks, not just neighbours. |
| 3 | 70 pts | The key is 7 characters long. Split the ciphertext into 7 columns; each column is a single-byte XOR you can break with letter frequencies (CyberChef: XOR Brute Force, or a few lines of Python). |
