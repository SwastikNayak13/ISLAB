from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

# Define the key and message
key = b"0123456789ABCDEF"  # AES-128 requires a 16-byte key
message = b"Sensitive Information"

# Create a cipher object using AES in CBC mode
iv = b"0123456789ABCDEF"  # Initialization Vector (must be 16 bytes)
cipher = AES.new(key, AES.MODE_CBC, iv)

# Pad the message to be a multiple of 16 bytes (128 bits)
padded_message = pad(message, AES.block_size)

# Encrypt the padded message
ciphertext = cipher.encrypt(padded_message)

# Create a new cipher object for decryption
decipher = AES.new(key, AES.MODE_CBC, iv)

# Decrypt the ciphertext
decrypted_padded_message = decipher.decrypt(ciphertext)

# Unpad the decrypted message
decrypted_message = unpad(decrypted_padded_message, AES.block_size)

# Convert ciphertext to hexadecimal for better readability
ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8')

# Show results
print("Ciphertext (in hexadecimal):", ciphertext_hex)
print("Decrypted Message:", decrypted_message.decode('utf-8'))
