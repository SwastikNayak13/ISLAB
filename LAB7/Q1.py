import random
import sympy


class Paillier:
    def __init__(self, bit_length=512):
        # Generate two large prime numbers p and q
        self.p = sympy.randprime(2 ** (bit_length - 1), 2 ** bit_length)
        self.q = sympy.randprime(2 ** (bit_length - 1), 2 ** bit_length)

        self.n = self.p * self.q
        self.n_squared = self.n ** 2
        self.g = self.n + 1  # Typically g is set to n + 1

        # Lambda value
        self.lam = (self.p - 1) * (self.q - 1)

    def encrypt(self, plaintext):
        """Encrypts a plaintext integer."""
        r = random.randint(1, self.n - 1)  # Random integer r
        # Ciphertext calculation
        ciphertext = (pow(self.g, plaintext, self.n_squared) * pow(r, self.n, self.n_squared)) % self.n_squared
        return ciphertext

    def decrypt(self, ciphertext):
        """Decrypts a ciphertext integer."""
        u = pow(ciphertext, self.lam, self.n_squared)
        plaintext = (u - 1) // self.n * sympy.mod_inverse(self.lam, self.n) % self.n
        return plaintext

    def add_encrypted(self, ciphertext1, ciphertext2):
        """Adds two ciphertexts."""
        return (ciphertext1 * ciphertext2) % self.n_squared


def main():
    # Initialize the Paillier encryption scheme
    paillier = Paillier()

    # Encrypt two integers
    plaintext1 = 15
    plaintext2 = 25
    ciphertext1 = paillier.encrypt(plaintext1)
    ciphertext2 = paillier.encrypt(plaintext2)

    print(f"Ciphertext of {plaintext1}: {ciphertext1}")
    print(f"Ciphertext of {plaintext2}: {ciphertext2}")

    # Perform addition on encrypted integers
    encrypted_sum = paillier.add_encrypted(ciphertext1, ciphertext2)
    print(f"Encrypted sum: {encrypted_sum}")

    # Decrypt the result
    decrypted_sum = paillier.decrypt(encrypted_sum)
    print(f"Decrypted sum: {decrypted_sum}")

    # Verify that it matches the sum of the original integers
    original_sum = plaintext1 + plaintext2
    print(f"Original sum: {original_sum}")
    assert decrypted_sum == original_sum, "Decrypted sum does not match the original sum!"


if __name__ == "__main__":
    main()
'''Explanation of the Code

    Paillier Class:
        Initialization: Generates two large prime numbers p and q, computes n, n_squared, g, and lambda.
        Encrypt Method: Takes a plaintext integer and encrypts it using the Paillier encryption formula.
        Decrypt Method: Decrypts a given ciphertext back to the plaintext.
        Add Encrypted Method: Allows for the addition of two ciphertexts, demonstrating the homomorphic property of the Paillier encryption scheme.

    Main Function:
        Initializes the Paillier encryption scheme.
        Encrypts two integers (15 and 25).
        Prints the ciphertexts of both integers.
        Adds the two ciphertexts without decrypting them.
        Decrypts the result of the addition and verifies it against the sum of the original integers.'''