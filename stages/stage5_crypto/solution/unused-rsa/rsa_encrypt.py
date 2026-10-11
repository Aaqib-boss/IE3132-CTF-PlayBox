from Crypto.Util.number import getPrime, bytes_to_long

# Short message dedicated to the RSA alternate path
plaintext = b"CASE{rsa_low_exponent_confirmed}"

p, q = getPrime(1024), getPrime(1024)
n = p * q
e = 3

m = bytes_to_long(plaintext)
assert m**3 < n, "Message still too large - use bigger primes or shorter message"

c = pow(m, e, n)

with open("rsa_params.txt", "w") as f:
    f.write(f"n = {n}\n")
    f.write(f"e = {e}\n")
    f.write(f"c = {c}\n")

print("RSA encryption complete.")
print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")