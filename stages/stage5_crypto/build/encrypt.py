def repeating_xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

with open("evidence.txt", "rb") as f:
    plaintext = f.read()

key = b"ledger7"  # short key, good for a fair index-of-coincidence attack

ciphertext = repeating_xor(plaintext, key)

with open("evidence.enc", "wb") as f:
    f.write(ciphertext)

print(f"Encrypted {len(plaintext)} bytes with key: {key}")