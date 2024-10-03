import random
import math

class RSA:
    def __init__(self, bit_length=16):
        self.p = self.generate_prime(bit_length)
        self.q = self.generate_prime(bit_length)
        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)
        self.e = self.choose_e(self.phi_n)
        self.d = self.mod_inverse(self.e, self.phi_n)

    def generate_prime(self, bit_length):
        """Generate a prime number of specified bit length."""
        while True:
            num = random.getrandbits(bit_length)
            if self.is_prime(num):
                return num

    def is_prime(self, num):
        """Check if a number is prime."""
        if num <= 1:
            return False
        if num <= 3:
            return True
        if num % 2 == 0 or num % 3 == 0:
            return False
        i = 5
        while i * i <= num:
            if num % i == 0 or num % (i + 2) == 0:
                return False
            i += 6
        return True

    def choose_e(self, phi_n):
        """Choose an integer e such that 1 < e < phi_n and gcd(e, phi_n) = 1."""
        e = 3
        while math.gcd(e, phi_n) != 1:
            e += 2
        return e

    def mod_inverse(self, a, m):
        """Compute the modular inverse of a under modulo m."""
        m0, x0, x1 = m, 0, 1
        if m == 1:
            return 0
        while a > 1:
            # q is quotient
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        if x1 < 0:
            x1 += m0
        return x1

    def encrypt(self, plaintext):
        """Encrypt a plaintext integer."""
        return pow(plaintext, self.e, self.n)

    def decrypt(self, ciphertext):
        """Decrypt a ciphertext integer."""
        return pow(ciphertext, self.d, self.n)

    def multiply_encrypted(self, ciphertext1, ciphertext2):
        """Multiply two ciphertexts."""
        return (ciphertext1 * ciphertext2) % self.n


def main():
    # Initialize the RSA encryption scheme
    rsa = RSA()

    # Encrypt two integers
    plaintext1 = 7
    plaintext2 = 3
    ciphertext1 = rsa.encrypt(plaintext1)
    ciphertext2 = rsa.encrypt(plaintext2)

    print(f"Ciphertext of {plaintext1}: {ciphertext1}")
    print(f"Ciphertext of {plaintext2}: {ciphertext2}")

    # Perform multiplication on encrypted integers
    encrypted_product = rsa.multiply_encrypted(ciphertext1, ciphertext2)
    print(f"Encrypted product: {encrypted_product}")

    # Decrypt the result
    decrypted_product = rsa.decrypt(encrypted_product)
    print(f"Decrypted product: {decrypted_product}")

    # Verify that it matches the product of the original integers
    original_product = plaintext1 * plaintext2
    print(f"Original product: {original_product}")
    assert decrypted_product == original_product, "Decrypted product does not match the original product!"


if __name__ == "__main__":
    main()

'''Explanation of the Code

    RSA Class:
        Initialization: Generates two prime numbers p and q, calculates the modulus n, and computes phi_n. It also chooses an appropriate public exponent e and calculates the private exponent d.
        Generate Prime: Creates a prime number of specified bit length.
        Is Prime: Checks if a number is prime using trial division.
        Choose e: Selects e such that it is coprime to phi_n.
        Mod Inverse: Computes the modular inverse of e modulo phi_n.
        Encrypt: Encrypts an integer using the public key.
        Decrypt: Decrypts a ciphertext using the private key.
        Multiply Encrypted: Multiplies two ciphertexts, showcasing the multiplicative homomorphic property of RSA.

    Main Function:
        Initializes the RSA encryption scheme.
        Encrypts two integers (7 and 3).
        Prints the ciphertexts of both integers.
        Multiplies the two ciphertexts without decrypting them.
        Decrypts the result of the multiplication and verifies it against the product of the original integers.'''