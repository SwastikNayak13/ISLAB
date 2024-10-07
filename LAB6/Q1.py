import random
from hashlib import sha256

# Generate large prime number p, generator g, private key x, public key y
def generate_keys(bit_length=256):
    p = random.getrandbits(bit_length)
    g = random.randint(2, p-1)
    x = random.randint(1, p-1)  # Private key
    y = pow(g, x, p)  # Public key
    return p, g, x, y

# Hash function for the message
def hash_message(message):
    return int(sha256(message.encode('utf-8')).hexdigest(), 16)

# Signing function
def sign_message(message, p, g, x):
    h = hash_message(message)
    while True:
        k = random.randint(1, p-2)
        if gcd(k, p-1) == 1:
            break
    r = pow(g, k, p)
    s = (h - x * r) * pow(k, -1, p-1) % (p-1)
    return r, s

# Verification function
def verify_signature(message, r, s, p, g, y):
    h = hash_message(message)
    if not (0 < r < p):
        return False
    v1 = pow(g, h, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    return v1 == v2

# Helper function: Calculate gcd
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Example usage
if __name__ == "__main__":
    # Key generation
    p, g, x, y = generate_keys()

    # Message to sign
    message = "Hello, ElGamal Digital Signature!"

    # Signing the message
    r, s = sign_message(message, p, g, x)
    print(f"Signature: (r, s) = ({r}, {s})")

    # Verifying the signature
    valid = verify_signature(message, r, s, p, g, y)
    print(f"Signature valid: {valid}")
