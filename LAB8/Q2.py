from phe import paillier
import re
from collections import defaultdict

# 2a. Generate a dataset (text corpus of at least ten documents)
documents = {
    1: "the quick brown fox jumps over the lazy dog",
    2: "never jump over the lazy dog quickly",
    3: "brown dog jumps over a quick fox",
    4: "lazy dogs are not quick to jump",
    5: "quick thinking wins the race over laziness",
    6: "the fox is brown and quick",
    7: "jumps happen fast with quick thinking",
    8: "the lazy dog is fast but not quick",
    9: "brown foxes are quick and lazy dogs are not",
    10: "think quickly, jump fast, and win the race"
}

# 2b. Implement encryption and decryption functions (Paillier cryptosystem)
public_key, private_key = paillier.generate_paillier_keypair()

# Encryption function
def encrypt_word(word, public_key):
    encrypted_word = [public_key.encrypt(ord(char)) for char in word]
    return encrypted_word

# Decryption function
def decrypt_word(encrypted_word, private_key):
    decrypted_word = ''.join([chr(private_key.decrypt(char)) for char in encrypted_word])
    return decrypted_word

# 2c. Create an encrypted index (inverted index)

# Create a simple inverted index mapping words to document IDs
def create_inverted_index(docs):
    inverted_index = defaultdict(list)
    for doc_id, text in docs.items():
        words = set(re.findall(r'\w+', text.lower()))  # Tokenizing words from the document
        for word in words:
            inverted_index[word].append(doc_id)
    return inverted_index

# Build the inverted index
inverted_index = create_inverted_index(documents)

# Encrypt the inverted index using Paillier encryption
encrypted_index = {}
for word, doc_ids in inverted_index.items():
    encrypted_word = encrypt_word(word, public_key)
    encrypted_index[tuple(encrypted_word)] = doc_ids

# 2d. Implement the search function

# Encrypt the search query
def encrypt_query(query, public_key):
    query_words = re.findall(r'\w+', query.lower())
    encrypted_query = [encrypt_word(word, public_key) for word in query_words]
    return encrypted_query

# Search the encrypted index
def search_encrypted_index(encrypted_query, encrypted_index, private_key):
    matching_doc_ids = set()

    for enc_word in encrypted_query:
        decrypted_query_word = decrypt_word(enc_word, private_key)
        
        for encrypted_word, doc_ids in encrypted_index.items():
            if decrypt_word(encrypted_word, private_key) == decrypted_query_word:
                matching_doc_ids.update(doc_ids)
                
    return list(matching_doc_ids)

# Take user input for search
search_term = input("Enter the search query: ")  # Taking input from the user

# Encrypt the query
encrypted_query = encrypt_query(search_term, public_key)

# Search in the encrypted index
matching_doc_ids = search_encrypted_index(encrypted_query, encrypted_index, private_key)

# Output the matching document IDs
if matching_doc_ids:
    print(f"Documents containing the words '{search_term}': {matching_doc_ids}")
else:
    print(f"No documents found containing the words '{search_term}'.")

'''Explanation:

    Dataset Generation (Step 2a):
        Created a small corpus of 10 documents containing several words.

    Encryption & Decryption Functions (Step 2b):
        The Paillier cryptosystem is used to encrypt each character of a word.
        The decryption function is used to reconstruct the word from its encrypted form.

    Encrypted Inverted Index (Step 2c):
        A basic inverted index is created by mapping words to document IDs.
        Each word in the index is encrypted using the Paillier public key.

    Search Function (Step 2d):
        The search term is encrypted with the public key and searched against the encrypted index.
        Matching document IDs are decrypted and returned as output.'''

