from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from collections import defaultdict
from Crypto.Random import get_random_bytes


# Step 1: Generate a text corpus (10 documents)
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

# AES encryption and decryption setup for ECB mode
key = get_random_bytes(16)  # Generate a random key
cipher = AES.new(key, AES.MODE_ECB)  # Using ECB mode

# AES encryption function
def encrypt_data(data, cipher):
    data_bytes = pad(data.encode(), AES.block_size)  # Pad the data to match block size
    encrypted_bytes = cipher.encrypt(data_bytes)  # Encrypt the data
    return base64.b64encode(encrypted_bytes).decode()  # Encode in base64 for readability

# AES decryption function
def decrypt_data(encrypted_data, cipher):
    encrypted_bytes = base64.b64decode(encrypted_data.encode())
    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
    return decrypted_bytes.decode()

# Step 2a: Build the inverted index (word -> list of document IDs)
def build_inverted_index(docs):
    inverted_index = defaultdict(list)
    for doc_id, doc in enumerate(docs):
        words = doc.lower().split()
        for word in set(words):  # Avoid duplicates
            inverted_index[word].append(doc_id)
    return inverted_index

# Step 2b: Encrypt the index (word -> encrypted document IDs)
def encrypt_inverted_index(inverted_index, cipher):
    encrypted_index = {}
    for word, doc_ids in inverted_index.items():
        encrypted_word = encrypt_data(word, cipher)  # Encrypt word
        encrypted_doc_ids = [encrypt_data(str(doc_id), cipher) for doc_id in doc_ids]  # Encrypt document IDs
        encrypted_index[encrypted_word] = encrypted_doc_ids
    return encrypted_index

# Encrypt a search query
def encrypt_query(query, cipher):
    return encrypt_data(query, cipher)

# Search the encrypted index
def search_encrypted_index(encrypted_query, encrypted_inverted_index):
    for encrypted_word, encrypted_doc_ids in encrypted_inverted_index.items():
        if encrypted_word == encrypted_query:
            return encrypted_doc_ids
    return []

# Decrypt the list of document IDs
def decrypt_document_ids(encrypted_doc_ids, cipher):
    decrypted_doc_ids = [decrypt_data(doc_id, cipher) for doc_id in encrypted_doc_ids]
    return decrypted_doc_ids

# Main function
def main():
    # Step 1: Build the inverted index from documents
    inverted_index = build_inverted_index(documents)

    # Step 2: Encrypt the inverted index using AES encryption in ECB mode
    cipher_encrypt = AES.new(key, AES.MODE_ECB)  # ECB mode
    encrypted_inverted_index = encrypt_inverted_index(inverted_index, cipher_encrypt)

    # Step 3: Take search query from the user
    search_query = input("Enter a search query: ").lower()

    # Step 4: Encrypt the search query
    encrypted_query = encrypt_query(search_query, cipher_encrypt)

    # Step 5: Search the encrypted index for matching encrypted document IDs
    encrypted_doc_ids = search_encrypted_index(encrypted_query, encrypted_inverted_index)

    # Step 6: Decrypt and display the corresponding document IDs
    if encrypted_doc_ids:
        cipher_decrypt = AES.new(key, AES.MODE_ECB)  # ECB mode
        decrypted_doc_ids = decrypt_document_ids(encrypted_doc_ids, cipher_decrypt)
        print(f"Documents matching the query '{search_query}':")
        for doc_id in decrypted_doc_ids:
            print(f"Document {int(doc_id) + 1}: {documents[int(doc_id)]}")
    else:
        print(f"No documents found for the query '{search_query}'.")

if __name__ == "__main__":
    main()
