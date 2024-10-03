from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

# Define the key and message
key = b"A1B2C3D4"  # DES key must be 8 bytes
message = b"Confidential Data"

# Create a DES cipher object
cipher = DES.new(key, DES.MODE_ECB)

# Pad the message to be a multiple of 8 bytes (64 bits)
padded_message = pad(message, DES.block_size)

# Encrypt the padded message
ciphertext = cipher.encrypt(padded_message)

# Decrypt the ciphertext
decipher = DES.new(key, DES.MODE_ECB)
decrypted_padded_message = decipher.decrypt(ciphertext)

# Unpad the decrypted message
decrypted_message = unpad(decrypted_padded_message, DES.block_size)

# Convert ciphertext to hexadecimal for better readability
ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8')

# Show results
print("Ciphertext (in hexadecimal):", ciphertext_hex)
print("Decrypted Message:", decrypted_message.decode('utf-8'))
