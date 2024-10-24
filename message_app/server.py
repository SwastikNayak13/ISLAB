import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

HOST = '127.0.0.1'
PORT = 5678
LISTENER_LIMIT = 5
active_clients = []

# AES encryption key and IV (16 bytes each for AES-128)
AES_KEY = b'your_key_1234567'  # 16 bytes key
AES_IV = b'your_iv_12345678'  # 16 bytes IV

def encrypt_message(message):
    encryptor = Cipher(algorithms.AES(AES_KEY), modes.CFB(AES_IV), backend=default_backend()).encryptor()
    encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return encrypted_message

# Function to decrypt the message using AES
def decrypt_message(encrypted_message):
    decryptor = Cipher(algorithms.AES(AES_KEY), modes.CFB(AES_IV), backend=default_backend()).decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message.decode('utf-8')

# Function to listen for upcoming messages from a client
def listen_for_messages(client, username):
    while 1:
        encrypted_message = client.recv(2048)
        if encrypted_message:
            decrypted_message = decrypt_message(encrypted_message)

            # Display both encrypted and decrypted message
            ##print(f"Decrypted message from {username}: {decrypted_message}")

            final_msg = f"{username}~{decrypted_message}"
            final_msg1 = encrypt_message(final_msg)
            send_messages_to_all(str(final_msg1))
        else:
            print(f"The message sent from client {username} is empty")

# Function to send a message to a single client
def send_message_to_client(client, message):
    client.sendall(message.encode())

# Function to send any new message to all clients
def send_messages_to_all(message):
    for user in active_clients:
        send_message_to_client(user[1], message)

# Function to handle client
def client_handler(client):
    while 1:
        username = client.recv(2048).decode('utf-8')
        if username != '':
            active_clients.append((username, client))
            prompt_message = "SERVER~" + f"{username} has joined the chat."
            send_messages_to_all(prompt_message)
            break
        else:
            print("Client username is empty")

    threading.Thread(target=listen_for_messages, args=(client, username)).start()

# Main function
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((HOST, PORT))
        print(f"Running the server on {HOST}:{PORT}")
    except:
        print(f"Unable to bind to host {HOST} and port {PORT}")

    server.listen(LISTENER_LIMIT)

    while 1:
        client, address = server.accept()
        print(f"Successfully connected to client {address[0]}:{address[1]}")
        threading.Thread(target=client_handler, args=(client,)).start()

if __name__ == '__main__':
    main()
