import socket
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

# Chat log file
CHAT_LOG_FILE = "chat_logs.txt"

# Function to generate a random 256-bit AES key
def generate_random_aes_key():
    return os.urandom(32)  # 256-bit key (32 bytes)

# Function to generate an RSA private/public key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt messages using AES
def encrypt_message_aes(message, key):
    IV = os.urandom(16)  # Random 128-bit IV for each message
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message + (16 - len(message) % 16) * ' '  # Padding with spaces
    encrypted_message = encryptor.update(padded_message.encode()) + encryptor.finalize()
    return base64.b64encode(IV + encrypted_message).decode()  # Return IV + encrypted message

# Function to encrypt messages using RSA (for logging)
def encrypt_message_rsa(message, public_key):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_message).decode()  # Return encrypted message in base64

# Function to log messages securely using RSA encryption
def log_message(username, message, rsa_public_key):
    encrypted_message = encrypt_message_rsa(message, rsa_public_key)  # Encrypt the message with RSA for logs
    log_entry = f"{username}: {encrypted_message}"  # Format log entry
    with open(CHAT_LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

# Function to handle client communication
def handle_client(client_socket, address, rsa_public_key):
    try:
        username = client_socket.recv(1024).decode('utf-8')  # Receive username
        print(f"[NEW CONNECTION] {address} connected with username: {username}")

        # Generate a new AES key for this session
        aes_key = generate_random_aes_key()
        
        # Send the AES key to the client (you should use a secure method to send it in a real-world scenario)
        client_socket.send(aes_key)

        while True:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                if message:
                    log_message(username, message, rsa_public_key)  # Log encrypted message using RSA
                    broadcast_message(f"{username}: {message}", client_socket, aes_key)  # Broadcast plaintext
                else:
                    break
            except:
                print(f"[ERROR] Communication error with {address}.")
                break
    finally:
        client_socket.close()
        print(f"[DISCONNECTED] {address} disconnected.")

# Function to broadcast plaintext messages to clients
def broadcast_message(message, sender_socket, key):
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message.encode('utf-8'))
            except:
                client.close()
                clients.remove(client)

# Server setup
server_ip = "0.0.0.0"
server_port = 12345
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((server_ip, server_port))
server_socket.listen(5)
clients = []

# Generate RSA keys for logging
private_key, public_key = generate_rsa_key_pair()

print("[STARTING] Server is starting...")

# Main loop to accept client connections
while True:
    client_socket, client_address = server_socket.accept()
    clients.append(client_socket)
    print(f"[NEW CONNECTION] {client_address} connected.")
    thread = threading.Thread(target=handle_client, args=(client_socket, client_address, public_key))
    thread.start()
