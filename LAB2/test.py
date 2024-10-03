def additive_cipher(plaintext, key):
    encrypted = ""
    decrypted = ""

    # Encrypting
    for char in plaintext:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a') #will be subtracted while operations to get the alphabet in the 0 to 25 range
            encrypted += chr((ord(char) - offset + key) % 26 + offset)
        else:
            encrypted += char

    # Decrypting
    for char in encrypted:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            decrypted += chr((ord(char) - offset - key + 26) % 26 + offset)
        else:
            decrypted += char

    return encrypted, decrypted


def multiplicative_cipher(plaintext, key):
    # Multiplicative inverse of 15 mod 26 is 7
    inverse_key = 7
    encrypted = ""
    decrypted = ""

    # Encrypting
    for char in plaintext:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            encrypted += chr(((ord(char) - offset) * key) % 26 + offset)
        else:
            encrypted += char

    # Decrypting
    for char in encrypted:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            decrypted += chr(((ord(char) - offset) * inverse_key) % 26 + offset)
        else:
            decrypted += char

    return encrypted, decrypted


def affine_cipher(plaintext, key1, key2):
    # Multiplicative inverse of 15 mod 26 is 7
    inverse_key1 = 7
    encrypted = ""
    decrypted = ""

    # Encrypting
    for char in plaintext:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            encrypted += chr(((ord(char) - offset) * key1 + key2) % 26 + offset)
        else:
            encrypted += char

    # Decrypting
    for char in encrypted:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            decrypted += chr(((ord(char) - offset - key2 + 26) * inverse_key1) % 26 + offset)
        else:
            decrypted += char

    return encrypted, decrypted


message = "I am learning information security"

# Additive cipher with key = 20
additive_encrypted, additive_decrypted = additive_cipher(message, 20)
print(f"Additive Cipher:\nEncrypted: {additive_encrypted}\nDecrypted: {additive_decrypted}\n")

# Multiplicative cipher with key = 15
multiplicative_encrypted, multiplicative_decrypted = multiplicative_cipher(message, 15)
print(f"Multiplicative Cipher:\nEncrypted: {multiplicative_encrypted}\nDecrypted: {multiplicative_decrypted}\n")

# Affine cipher with key = (15, 20)
affine_encrypted, affine_decrypted = affine_cipher(message, 15, 20)
print(f"Affine Cipher:\nEncrypted: {affine_encrypted}\nDecrypted: {affine_decrypted}")