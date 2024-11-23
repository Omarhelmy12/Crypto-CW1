import socket
import threading
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

# File to store hashed credentials
CREDENTIALS_FILE = "credentials.txt"

# Function to generate AES decryption key from server-provided key
def decrypt_message(encrypted_message, key):
    # Extract the IV from the start of the message
    iv = base64.b64decode(encrypted_message)[:16]
    encrypted_message = base64.b64decode(encrypted_message)[16:]  # Remove IV part
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message.decode('utf-8').rstrip()  # Remove padding

# Hashing function for passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to handle signup
def signup():
    print("\n[Signup]")
    username = input("Enter username: ")
    password = input("Enter password: ")
    hashed_password = hash_password(password)

    # Check if the username exists
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as f:
            for line in f:
                stored_user, _ = line.strip().split(":")
                if stored_user == username:
                    print("Username already exists. Please try again.")
                    return None

    # Save new credentials
    with open(CREDENTIALS_FILE, "a") as f:
        f.write(f"{username}:{hashed_password}\n")
    print("Signup successful!")
    return username

# Function to handle login
def login():
    print("\n[Login]")
    username = input("Enter username: ")
    password = input("Enter password: ")
    hashed_password = hash_password(password)

    # Verify credentials
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as f:
            for line in f:
                stored_user, stored_hashed_password = line.strip().split(":")
                if stored_user == username and stored_hashed_password == hashed_password:
                    print("Login successful!")
                    return username
    print("Invalid credentials.")
    return None

# Function to receive messages
def receive_messages(client_socket):
    aes_key = None
    while True:
        try:
            # Receive the AES key from the server
            if not aes_key:
                aes_key = client_socket.recv(1024)  # Receive the AES key
                continue

            # Receive the message
            received_message = client_socket.recv(1024).decode('utf-8')
            if received_message:
                print(f"Received message: {received_message}")  # Display the plaintext received
        except Exception as e:
            print(f"[ERROR] Lost connection to the server: {e}")
            break

# Function to send messages
def chat(client_socket, username):
    print("\n[Chatroom]")
    print("Type your message and press Enter to send (type 'exit' to leave).")

    # Start receiving thread
    thread = threading.Thread(target=receive_messages, args=(client_socket,))
    thread.start()

    while True:
        message = input()
        if message.lower() == "exit":
            client_socket.close()
            print("You left the chatroom.")
            break

        # Send plaintext message to the server
        client_socket.send(message.encode('utf-8'))

# Main function
def main():
    server_ip = "127.0.0.1"
    server_port = 12345
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))
    print("[CONNECTED] Connected to the server!")

    username = None
    while not username:
        choice = input("\nDo you want to login or signup? (login/signup): ").strip().lower()
        if choice == "signup":
            username = signup()
        elif choice == "login":
            username = login()
        else:
            print("Invalid option. Please try again.")

    # Send the username to the server
    client_socket.send(username.encode('utf-8'))

    # Start chat
    chat(client_socket, username)

if __name__ == "__main__":
    main()
