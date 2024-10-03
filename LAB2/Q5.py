import numpy as np
import binascii

# AES S-Box
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34,
    0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04,
    0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07,
    0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09,
    0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52,
    0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53,
    0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a,
    0x6c, 0x7c, 0x1d, 0x9c, 0xeb, 0x2f, 0x63, 0x65,
    0x3f, 0x7b, 0x6c, 0x84, 0xf1, 0x8c, 0xc3, 0xa1,
    0xf7, 0x9c, 0x0a, 0xc9, 0xa6, 0x5f, 0x67, 0x9a,
    0x2f, 0xc6, 0x6b, 0xd5, 0x38, 0xf8, 0xd6, 0xd7,
    0x19, 0x6b, 0x56, 0x38, 0x7c, 0xb8, 0xb5, 0x8c,
]

# Inverse S-Box
INV_S_BOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc8, 0x9c,
    0x78, 0x25, 0x2e, 0x1c, 0xa6, 0x61, 0x56, 0x63,
    0x1d, 0xe4, 0x95, 0x36, 0xe0, 0xb2, 0xe1, 0x01,
]

# Round constants (Rcon)
RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36
]


def key_expansion(key):
    """ Expand the key for AES-192 """
    key_schedule = [0] * 52  # 52 words for AES-192
    key_schedule[:6] = [int.from_bytes(key[i:i + 4], byteorder='big') for i in range(0, 24, 4)]

    for i in range(6, 52):
        temp = key_schedule[i - 1]
        if i % 6 == 0:
            temp = (sub_word(rot_word(temp)) ^ (RCON[i // 6 - 1] << 24))
        key_schedule[i] = key_schedule[i - 6] ^ temp

    return key_schedule


def sub_word(word):
    """ Apply S-Box substitution to a 4-byte word """
    return (S_BOX[(word >> 24) & 0xFF] << 24) | \
        (S_BOX[(word >> 16) & 0xFF] << 16) | \
        (S_BOX[(word >> 8) & 0xFF] << 8) | \
        (S_BOX[word & 0xFF])


def rot_word(word):
    """ Rotate a 4-byte word """
    return ((word << 8) & 0xFFFFFFFF) | (word >> 24)


def add_round_key(state, round_key):
    """ Add round key to state """
    return state ^ round_key


def sub_bytes(state):
    """ Apply S-Box substitution to the state """
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]
    return state


def shift_rows(state):
    """ Perform the ShiftRows operation """
    return np.array([
        [state[0][0], state[0][1], state[0][2], state[0][3]],
        [state[1][1], state[1][2], state[1][3], state[1][0]],
        [state[2][2], state[2][3], state[2][0], state[2][1]],
        [state[3][3], state[3][0], state[3][1], state[3][2]],
    ])


def mix_columns(state):
    """ Perform the MixColumns operation """
    for i in range(4):
        a = state[:, i].copy()
        state[0][i] = (2 * a[0]) ^ (3 * a[1]) ^ a[2] ^ a[3]
        state[1][i] = a[0] ^ (2 * a[1]) ^ (3 * a[2]) ^ a[3]
        state[2][i] = a[0] ^ a[1] ^ (2 * a[2]) ^ (3 * a[3])
        state[3][i] = (3 * a[0]) ^ a[1] ^ a[2] ^ (2 * a[3])
    return state


def aes_encrypt(plaintext, key):
    """ Encrypt plaintext using AES-192 """
    key_schedule = key_expansion(key)

    # Initial round
    state = np.array(plaintext).reshape((4, 4))
    state = add_round_key(state.flatten(), key_schedule[:6])

    # Main rounds
    for i in range(1, 12):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state.flatten(), key_schedule[i * 6:(i + 1) * 6])

    # Final round
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state.flatten(), key_schedule[12 * 6:])

    return state.flatten()


# Define the key and message
key = b"FEDCBA9876543210FEDCBA9876543210"[:24]  # Use only the first 24 bytes for AES-192
message = b"Top Secret Data"

# Padding the message to 16 bytes
block_size = 16
padded_message = message + b'\x00' * (block_size - len(message) % block_size)

# Convert message to a 4x4 matrix
plaintext = np.array(padded_message).reshape((4, 4)).T

# Encrypt the message
ciphertext = aes_encrypt(plaintext, key)

# Convert ciphertext to hexadecimal for better readability
ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8')

# Show results
print("Ciphertext (in hexadecimal):", ciphertext_hex)


