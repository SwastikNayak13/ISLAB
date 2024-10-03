import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# RSA Encryption and Decryption
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(public_key, plaintext):
    # Generate a symmetric key
    symmetric_key = os.urandom(32)  # 256-bit AES key

    # Encrypt the plaintext using AES
    iv = os.urandom(16)  # Generate a random IV for AES
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = iv + encryptor.update(plaintext) + encryptor.finalize()  # Prepend IV to ciphertext

    # Encrypt the symmetric key using RSA
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key, ciphertext


def rsa_decrypt(private_key, encrypted_key, ciphertext):
    # Decrypt the symmetric key using RSA
    symmetric_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Extract IV from the ciphertext
    iv = ciphertext[:16]  # First 16 bytes are the IV
    ciphertext = ciphertext[16:]  # Remaining bytes are the actual ciphertext

    # Decrypt the ciphertext using AES
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))  # Use the same IV
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext


# ElGamal Encryption and Decryption
def generate_elgamal_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def elgamal_encrypt(public_key, plaintext):
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_key.public_key()

    shared_secret = ephemeral_key.exchange(ec.ECDH(), public_key)
    symmetric_key = hashes.Hash(hashes.SHA256())
    symmetric_key.update(shared_secret)
    derived_key = symmetric_key.finalize()

    cipher_text = bytes((b1 ^ b2) for b1, b2 in zip(plaintext, derived_key))

    return ephemeral_public_key, cipher_text


def elgamal_decrypt(private_key, ephemeral_public_key, cipher_text):
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
    symmetric_key = hashes.Hash(hashes.SHA256())
    symmetric_key.update(shared_secret)
    derived_key = symmetric_key.finalize()

    decrypted_text = bytes((b1 ^ b2) for b1, b2 in zip(cipher_text, derived_key))

    return decrypted_text


# Generate random messages of specified size
def generate_random_message(size_kb):
    return os.urandom(size_kb * 1024)


# Performance measurement for RSA
def rsa_performance(size_kb):
    # Generate RSA keys
    start_time = time.time()
    rsa_private_key, rsa_public_key = generate_rsa_keys()
    key_gen_time = time.time() - start_time

    # Generate message
    message = generate_random_message(size_kb)

    # Measure encryption time
    start_time = time.time()
    encrypted_key, rsa_ciphertext = rsa_encrypt(rsa_public_key, message)
    encryption_time = time.time() - start_time

    # Measure decryption time
    start_time = time.time()
    rsa_decrypted_message = rsa_decrypt(rsa_private_key, encrypted_key, rsa_ciphertext)
    decryption_time = time.time() - start_time

    return key_gen_time, encryption_time, decryption_time, message, rsa_decrypted_message


# ElGamal Performance
def elgamal_performance(size_kb):
    # Generate ElGamal keys
    start_time = time.time()
    elgamal_private_key, elgamal_public_key = generate_elgamal_keys()
    key_gen_time = time.time() - start_time

    # Generate message
    message = generate_random_message(size_kb)

    # Measure encryption time
    start_time = time.time()
    ephemeral_public_key, elgamal_ciphertext = elgamal_encrypt(elgamal_public_key, message)
    encryption_time = time.time() - start_time

    # Measure decryption time
    start_time = time.time()
    elgamal_decrypted_message = elgamal_decrypt(elgamal_private_key, ephemeral_public_key, elgamal_ciphertext)
    decryption_time = time.time() - start_time

    return key_gen_time, encryption_time, decryption_time, message, elgamal_decrypted_message


# Main Function
def main():
    sizes_kb = [1, 10]  # Test sizes in KB

    for size in sizes_kb:
        print(f"\nTesting with message size: {size} KB")

        # RSA Performance
        rsa_key_gen_time, rsa_encryption_time, rsa_decryption_time, rsa_message, rsa_decrypted_message = rsa_performance(
            size)
        print(f"RSA Key Generation Time: {rsa_key_gen_time:.6f} seconds")
        print(f"RSA Encryption Time: {rsa_encryption_time:.6f} seconds")
        print(f"RSA Decryption Time: {rsa_decryption_time:.6f} seconds")
        assert rsa_message == rsa_decrypted_message, "RSA Decryption failed"

        # ElGamal Performance
        elgamal_key_gen_time, elgamal_encryption_time, elgamal_decryption_time, elgamal_message, elgamal_decrypted_message = elgamal_performance(
            size)
        print(f"ElGamal Key Generation Time: {elgamal_key_gen_time:.6f} seconds")
        print(f"ElGamal Encryption Time: {elgamal_encryption_time:.6f} seconds")
        print(f"ElGamal Decryption Time: {elgamal_decryption_time:.6f} seconds")
        assert elgamal_message == elgamal_decrypted_message, "ElGamal Decryption failed"


if __name__ == "__main__":
    main()
