from itertools import combinations

def hamming_distance(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

def guess_key_length(ciphertext: bytes, max_len: int = 15) -> int:
    scores = {}
    for keysize in range(2, max_len + 1):
        chunks = [ciphertext[i:i+keysize] for i in range(0, len(ciphertext) - keysize, keysize)]
        if len(chunks) < 4:
            continue
        pairs = list(combinations(chunks, 2))
        distances = [hamming_distance(a, b) / keysize for a, b in pairs]
        scores[keysize] = sum(distances) / len(distances)

    # Return the keysize with the lowest normalized distance
    return min(scores, key=scores.get)

def break_single_byte_xor(block: bytes) -> int:
    best_byte, best_score = 0, -1
    freq = "etaoin shrdlu"
    for key_byte in range(256):
        decoded = bytes(b ^ key_byte for b in block)
        score = sum(decoded.lower().count(c.encode()) for c in freq)
        if score > best_score:
            best_score = score
            best_byte = key_byte
    return best_byte

def recover_key(ciphertext: bytes, keysize: int) -> bytes:
    key = bytearray()
    for i in range(keysize):
        block = ciphertext[i::keysize]
        key.append(break_single_byte_xor(block))
    return bytes(key)

with open("../build/evidence.enc", "rb") as f:
    ciphertext = f.read()

keysize = guess_key_length(ciphertext)
key = recover_key(ciphertext, keysize)
plaintext = bytes(b ^ key[i % len(key)] for i, b in enumerate(ciphertext))

print(f"Guessed key length: {keysize}")
print(f"Recovered key: {key}")
print("Decrypted:\n")
print(plaintext.decode(errors="replace"))