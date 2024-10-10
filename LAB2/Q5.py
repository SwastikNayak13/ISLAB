from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii

# Key for AES-192 (must be 24 bytes = 192 bits)
key = bytes.fromhex("FEDCBA9876543210FEDCBA9876543210FEDCBA98")

# Message to encrypt
message = "Top Secret Data"

# Convert the message to bytes
message_bytes = message.encode()

# Pad the message to be a multiple of 16 bytes
message_padded = pad(message_bytes, AES.block_size)

# Create AES cipher in ECB mode (other modes like CBC, GCM can also be used)
cipher = AES.new(key, AES.MODE_ECB)

# Encrypt the message
encrypted_message = cipher.encrypt(message_padded)

# Convert encrypted message to hexadecimal for easy viewing
encrypted_message_hex = binascii.hexlify(encrypted_message).decode()

# Print the encrypted message
print(f"Encrypted Message (Hex): {encrypted_message_hex}")



