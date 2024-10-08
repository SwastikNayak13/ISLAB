from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from collections import defaultdict

# AES key for encryption/decryption
key = get_random_bytes(16)  # AES key of size 128 bits

# Sample text corpus (10 documents)
documents = [
    "The quick brown fox jumps over the lazy dog",
    "Symmetric encryption ensures confidentiality",
    "Searchable encryption allows secure search over encrypted data",
    "Cloud storage solutions need to protect privacy",
    "Encryption and decryption use secret keys",
    "Data security is essential in today's digital world",
    "Inverted indexes enable fast full-text searches",
    "Encryption must be strong to prevent unauthorized access",
    "Information retrieval in encrypted form is challenging",
    "Advanced cryptography techniques improve security"
]


# AES ECB Encryption function (for words)
def encrypt_word_ecb(word, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(word.encode(), AES.block_size))
    return ct_bytes


# AES ECB Decryption function (for debugging, not strictly needed)
def decrypt_word_ecb(encrypted_word, key):
    cipher = AES.new(key, AES.MODE_ECB)
    pt = unpad(cipher.decrypt(encrypted_word), AES.block_size)
    return pt.decode()


# Build the inverted index (word -> list of document IDs)
def build_inverted_index(docs):
    inverted_index = defaultdict(list)
    for doc_id, doc in enumerate(docs):
        words = doc.lower().split()
        for word in set(words):  # using `set(words)` to avoid duplicates
            inverted_index[word].append(doc_id)
    return inverted_index


# Encrypt the words in the inverted index using AES-ECB
def encrypt_index_ecb(inverted_index, key):
    encrypted_index = {}
    for word, doc_ids in inverted_index.items():
        encrypted_word = encrypt_word_ecb(word, key)
        encrypted_index[encrypted_word] = doc_ids
    return encrypted_index


# Encrypt a search query using AES-ECB
def encrypt_query_ecb(query, key):
    encrypted_query = encrypt_word_ecb(query, key)
    return encrypted_query


# Search the encrypted index for the encrypted query
def search_encrypted_index(encrypted_query, encrypted_inverted_index):
    for encrypted_word, doc_ids in encrypted_inverted_index.items():
        if encrypted_word == encrypted_query:
            return doc_ids
    return []


# Main function
def main():
    # Step 1: Build the inverted index
    inverted_index = build_inverted_index(documents)

    # Step 2: Encrypt the inverted index using AES-ECB
    encrypted_inverted_index = encrypt_index_ecb(inverted_index, key)

    # Step 3: Take search query from the user
    search_query = input("Enter a search query: ").lower()

    # Step 4: Encrypt the search query using AES-ECB
    encrypted_query = encrypt_query_ecb(search_query, key)

    # Step 5: Search the encrypted index for matching document IDs
    matched_doc_ids = search_encrypted_index(encrypted_query, encrypted_inverted_index)

    # Step 6: Decrypt and display the corresponding documents
    if matched_doc_ids:
        print(f"Documents matching the query '{search_query}':")
        for doc_id in matched_doc_ids:
            print(f"Document {doc_id + 1}: {documents[doc_id]}")
    else:
        print(f"No documents found for the query '{search_query}'.")


if __name__ == "__main__":
    main()

'''Explanation:

    Dataset (documents): A list of 10 sample documents is created.
    AES Encryption/Decryption (encrypt_data/decrypt_data): Functions to encrypt and decrypt data using AES encryption.
    Inverted Index (build_inverted_index): A function to create an inverted index from the documents.
    Encrypting the Inverted Index (encrypt_index): The words in the inverted index are encrypted using AES encryption.
    Search Function (encrypt_query, search_encrypted_index): The search query is encrypted, and the encrypted index is searched for matches.
    Main Function: Handles user input, executes the search, and displays the results.

To run:

    Copy this code into a Python environment.
    You'll be prompted to enter a search query.
    The system will display matching documents based on the encrypted search.'''

'''It looks like the encryption of the search query and the encrypted index may not be matching due to the encryption process generating different ciphertexts for the same plaintext when using the AES Cipher Block Chaining (CBC) mode. In CBC mode, encryption produces different outputs even for the same plaintext due to the use of a unique initialization vector (IV) each time. This is likely why no documents were found for your search query.
Solution:

To fix this, we need to ensure that the same word (both in the index and query) is encrypted in a consistent manner. This can be done by encrypting only the word (query and index terms) with the same IV or using a deterministic encryption scheme (which produces the same ciphertext for the same input every time).

For simplicity, I'll modify the code to use AES Electronic Codebook (ECB) mode for encrypting the words in the inverted index and the query. In this mode, identical plaintext blocks are encrypted to identical ciphertext blocks, ensuring consistency for searching.
ECB Mode for Word Encryption: The encrypt_word_ecb function now uses AES.MODE_ECB to ensure that the same word gets the same encrypted value every time, making the search process work properly.
Inverted Index Encryption: The inverted index now encrypts the words using ECB mode.
Query Encryption: The search query is also encrypted using ECB mode, ensuring that the encryption matches the encrypted terms in the inverted index.'''