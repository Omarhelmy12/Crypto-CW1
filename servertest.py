import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

# Chat log file
CHAT_LOG_FILE = "chat_logs.txt"

# Function to generate a random 256-bit AES key
def generate_random_aes_key():
    return os.urandom(32)  # 256-bit key (32 bytes)

# Function to encrypt messages using AES
def encrypt_message(message, key):
    IV = os.urandom(16)  # Random 128-bit IV for each message
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message + (16 - len(message) % 16) * ' '  # Padding with spaces
    encrypted_message = encryptor.update(padded_message.encode()) + encryptor.finalize()
    return base64.b64encode(IV + encrypted_message).decode()  # Return IV + encrypted message

# Function to log messages securely
def log_message(username, message, key):
    encrypted_message = encrypt_message(message, key)  # Encrypt the message
    log_entry = f"{username}: {encrypted_message}"  # Format log entry
    with open(CHAT_LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

# Function to handle client communication
def handle_client(client_socket, address):
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
                    log_message(username, message, aes_key)  # Log encrypted message
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

print("[STARTING] Server is starting...")

# Main loop to accept client connections
while True:
    client_socket, client_address = server_socket.accept()
    clients.append(client_socket)
    print(f"[NEW CONNECTION] {client_address} connected.")
    thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
    thread.start()
