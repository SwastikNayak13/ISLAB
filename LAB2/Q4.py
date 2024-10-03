from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import binascii

# Define the key and message
key = b"1234567890ABCDEF1234567890ABCDEF"[:24] # Key for Triple DES (must be 24 bytes)
message = b"Classified Text"

# Create a 3DES cipher object in CBC mode
iv = b"12345678"  # Initialization Vector (must be 8 bytes)
cipher = DES3.new(key, DES3.MODE_CBC, iv)

# Pad the message to be a multiple of 8 bytes (64 bits)
padded_message = pad(message, DES3.block_size)

# Encrypt the padded message
ciphertext = cipher.encrypt(padded_message)

# Create a new cipher object for decryption
decipher = DES3.new(key, DES3.MODE_CBC, iv)

# Decrypt the ciphertext
decrypted_padded_message = decipher.decrypt(ciphertext)

# Unpad the decrypted message
decrypted_message = unpad(decrypted_padded_message, DES3.block_size)

# Convert ciphertext to hexadecimal for better readability
ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8')

# Show results
print("Ciphertext (in hexadecimal):", ciphertext_hex)
print("Decrypted Message:", decrypted_message.decode('utf-8'))
