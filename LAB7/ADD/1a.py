import random


class ElGamal:
    def __init__(self, p=None, g=None):
        self.p = p if p else self.generate_prime()
        self.g = g if g else random.randint(2, self.p - 2)
        self.x = random.randint(1, self.p - 2)  # Private key
        self.y = pow(self.g, self.x, self.p)  # Public key

    def generate_prime(self, bits=8):
        """Generate a prime number."""
        while True:
            num = random.getrandbits(bits)
            if self.is_prime(num):
                return num

    def is_prime(self, n):
        """Check if n is a prime number."""
        if n <= 1:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    def encrypt(self, m):
        """Encrypt the message m using ElGamal encryption."""
        k = random.randint(1, self.p - 2)
        c1 = pow(self.g, k, self.p)
        c2 = (m * pow(self.y, k, self.p)) % self.p
        return (c1, c2)

    def decrypt(self, c):
        """Decrypt the ciphertext c."""
        c1, c2 = c
        s = pow(c1, self.x, self.p)
        m = (c2 * mod_inverse(s, self.p)) % self.p
        return m

    def multiply_encrypted(self, c1, c2):
        """Multiply two encrypted messages."""
        c1a, c1b = c1
        c2a, c2b = c2
        result_c1 = (c1a * c2a) % self.p
        result_c2 = (c1b * c2b) % self.p
        return (result_c1, result_c2)


def mod_inverse(a, p):
    """Compute the modular inverse of a modulo p."""
    return pow(a, p - 2, p)


# Example usage
if __name__ == "__main__":
    elgamal = ElGamal()

    # Encrypt two integers
    m1 = 7
    m2 = 3
    c1 = elgamal.encrypt(m1)
    c2 = elgamal.encrypt(m2)

    # Multiply the encrypted messages
    c_mult = elgamal.multiply_encrypted(c1, c2)

    # Decrypt the result
    decrypted_result = elgamal.decrypt(c_mult)

    # Verify that it matches the product of the original integers
    assert decrypted_result == m1 * m2, "Homomorphic multiplication failed"
    print(f"Encrypted multiplication result: {c_mult}")
    print(f"Decrypted result matches the product: {decrypted_result}")
