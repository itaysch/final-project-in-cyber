import socket
import threading
import queue
import base64
import os
import protocol
import ast
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from tkinter import messagebox
import hashlib
import keyring


PORT = 9999  # port
HOST = "192.168.1.182"


# creating queues for the purpose of transferring data from the client to the tkInter application
message_queue = queue.Queue()
database_check_queue = queue.Queue()
database_check_new_chat_queue = queue.Queue()
offline_queue = queue.Queue()
delete_chat_queue = queue.Queue()
server_offline_queue = queue.Queue()
public_key_queue = queue.Queue()
new_group_queue = queue.Queue()


client_socket = None
received_message = None


lock = threading.Lock()


# this function get a socket, and returns true if the socket is open and false if not
def is_socket_open(sock):
    try:
        # This will raise an error if the socket is closed
        sock.send(b"")
        return True
    except socket.error:
        return False


# this function generates a random AES key
def generate_key():
    # Generate a random 256-bit (32-byte) AES key
    return get_random_bytes(32)


# this function generates a random IV
def generate_iv():
    # Generate a random 128-bit (16-byte) IV
    return get_random_bytes(16)


# this function generates the private and public RSA keys
def generate_rsa_keys():
    # Generate RSA keys
    rsa_key = RSA.generate(2048)
    rsa_public_key = rsa_key.publickey()
    return rsa_key, rsa_public_key


# this function gets a text and the key, iv, and encrypts the text with AES
def aes_encrypt(plaintext, key, iv):
    # Create an AES cipher object with the provided key, AES.MODE_CBC mode, and the given IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad the plaintext to match the block size (128 bits or 16 bytes for AES)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)

    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)

    return ciphertext


# this function gets a cipher and the key, iv, and decrypts the cipher with AES
def aes_decrypt(ciphertext, key, iv):
    # Create an AES cipher object with the provided key, AES.MODE_CBC mode, and the given IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext
    decrypted_data = cipher.decrypt(ciphertext)

    # Un pad the decrypted data
    plaintext = unpad(decrypted_data, AES.block_size)

    return plaintext.decode('utf-8')


# this function gets a message and encrypts it with RSA and AES
def encrypt_message(message_content, rsa_public_key_pem):
    try:
        rsa_public_key = RSA.import_key(rsa_public_key_pem)

        # Generate a random AES key and IV
        encryption_key = generate_key()
        iv = generate_iv()

        # Encrypt the AES key and IV using RSA
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        encrypted_aes_key_send = cipher_rsa.encrypt(encryption_key)
        encrypted_iv_send = cipher_rsa.encrypt(iv)

        # Encrypt the message using AES
        encrypted_message = aes_encrypt(message_content, encryption_key, iv)

        encrypted_aes_key_send_b64 = base64.b64encode(encrypted_aes_key_send).decode()
        encrypted_iv_send_b64 = base64.b64encode(encrypted_iv_send).decode()
        encrypted_message_b64 = base64.b64encode(encrypted_message).decode()

        response = f"{encrypted_aes_key_send_b64}|{encrypted_iv_send_b64}|{encrypted_message_b64}"
        return response

    except Exception as e:
        print(f"[ERROR] Exception: {str(e)}")
        import traceback
        traceback.print_exc()


# this function gets a rsa key and the data to decrypt and decrypts it with RSA and AES
def decrypt_message(rsa_key, data):
    encrypted_aes_key_b64, encrypted_iv_b64, encrypted_message_b64 = data.split("|")

    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
    encrypted_iv = base64.b64decode(encrypted_iv_b64)
    encrypted_message = base64.b64decode(encrypted_message_b64)

    # Decrypt the AES key and IV using RSA
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    decrypted_iv = cipher_rsa.decrypt(encrypted_iv)

    # Decrypt the message using AES
    cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CBC, decrypted_iv)
    decrypted_message = unpad(cipher_aes.decrypt(encrypted_message), AES.block_size)

    return decrypted_message


# this function gets a rsa key and the message list and the username to decrypt and decrypts it with RSA and AES
# this is for when the server sends the message history encrypted
def decrypt_messages_list(sender_rsa_key, messages, username):
    decrypted_messages = []
    for message in messages:
        message_id, chat_id, sender, receiver, message_content_receiver, message_content_sender, time_sent, message_type, filepath_sender = message

        if username == sender:
            encrypted_aes_key_b64, encrypted_iv_b64, encrypted_message_b64 = message_content_sender.split("|")

            encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
            encrypted_iv = base64.b64decode(encrypted_iv_b64)
            encrypted_message = base64.b64decode(encrypted_message_b64)

            # Decrypt the AES key and IV using RSA
            cipher_rsa = PKCS1_OAEP.new(sender_rsa_key)
            decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            decrypted_iv = cipher_rsa.decrypt(encrypted_iv)

            # Decrypt the message using AES
            cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CBC, decrypted_iv)
            decrypted_message_content = unpad(cipher_aes.decrypt(encrypted_message), AES.block_size)

            # Reconstruct the message with the decrypted message_content
            decrypted_message = (message_id, chat_id, sender, receiver, decrypted_message_content.decode(), time_sent, message_type, "Empty")

            decrypted_messages.append(decrypted_message)
        elif username == receiver:
            if filepath_sender == "Empty":
                encrypted_aes_key_b64, encrypted_iv_b64, encrypted_message_b64 = message_content_receiver.split("|")

                encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
                encrypted_iv = base64.b64decode(encrypted_iv_b64)
                encrypted_message = base64.b64decode(encrypted_message_b64)

                # Decrypt the AES key and IV using RSA
                cipher_rsa = PKCS1_OAEP.new(sender_rsa_key)
                decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
                decrypted_iv = cipher_rsa.decrypt(encrypted_iv)

                # Decrypt the message using AES
                cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CBC, decrypted_iv)
                decrypted_message_content = unpad(cipher_aes.decrypt(encrypted_message), AES.block_size)

                # Reconstruct the message with the decrypted message_content
                decrypted_message = (message_id, chat_id, sender, receiver, decrypted_message_content.decode(), time_sent, message_type, "Empty")

                decrypted_messages.append(decrypted_message)
            else:
                encrypted_aes_key_b64, encrypted_iv_b64, encrypted_message_b64 = filepath_sender.split("|")

                encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
                encrypted_iv = base64.b64decode(encrypted_iv_b64)
                encrypted_message = base64.b64decode(encrypted_message_b64)

                # Decrypt the AES key and IV using RSA
                cipher_rsa = PKCS1_OAEP.new(sender_rsa_key)
                decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
                decrypted_iv = cipher_rsa.decrypt(encrypted_iv)

                # Decrypt the message using AES
                cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CBC, decrypted_iv)
                decrypted_message_content = unpad(cipher_aes.decrypt(encrypted_message), AES.block_size)

                # Reconstruct the message with the decrypted message_content
                decrypted_message = (message_id, chat_id, sender, receiver, message_content_receiver, time_sent, message_type, decrypted_message_content.decode())

                decrypted_messages.append(decrypted_message)

    return decrypted_messages


def encrypt_file(filename, key):
    cipher = AES.new(key, AES.MODE_CBC)

    with open(filename, 'rb') as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Overwrite the original file with the ciphertext
    with open(filename, 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)


def decrypt_file(filename, key):
    with open(filename, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    # Overwrite the original file with the plaintext
    with open(filename, 'wb') as f:
        f.write(plaintext)


# this function get a username, password, and an identifier that says if the functionality is log in or sign up
# the function returns the server's response, if the user is logged in - it will return to him the message history
def validate_user(username, password, identifier):
    try:
        # connect to the temp socket
        check_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        check_socket.connect((HOST, PORT))
        server_offline_queue.put("SERVER_ONLINE")
        print("sending data to add to the server")

        msg_to_send = f"CHECK_CLIENT_IN_DATABASE;{username};{password};{identifier}"

        # if it is a log in
        if identifier == "LOG_IN":
            protocol.send(check_socket, msg_to_send)
        # if it is sign up
        elif identifier == "SIGN_UP":
            protocol.send(check_socket, msg_to_send)

        while True:
            response = protocol.receive(check_socket)
            print(f"response in validate_user")
            if response.startswith("MESSAGE_HISTORY;"):
                messages = response.split(";", 2)[2]
                chat_name = response.split(";", 2)[1]
                sender_rsa_key = None

                # Retrieve the key
                key_hex = keyring.get_password("myapplication", username)

                # Convert the hexadecimal string back to bytes
                key = bytes.fromhex(key_hex)
                decrypt_file(f"C:\\Users\\Public\\{username}_private.pem", key)

                # Load the private key
                with open(f"C:\\Users\\Public\\{username}_private.pem", "rb") as f:
                    sender_rsa_key = RSA.import_key(f.read())
                # Encrypt the private key file again
                encrypt_file(f"C:\\Users\\Public\\{username}_private.pem", key)

                # Parse the messages string back into a list of tuples
                messages = ast.literal_eval(messages)
                # decrypt the messages
                decrypted_messages = decrypt_messages_list(sender_rsa_key, messages, username)

                # put the message and chat in the queue
                message_queue.put((chat_name, decrypted_messages))

            elif response == "no msg":
                break
            else:
                database_check_queue.put(response)
                if response in ["USER_IN_DATABASE", "PASSWORD_INCORRECT", "USER_DOES_NOT_EXIST", "SIGNED_UP", "ALREADY_EXISTS"] or response.startswith("PASSWORD_INVALID"):
                    print("closing socket")
                    # clos the temp socket
                    check_socket.close()
                    break

    except ConnectionRefusedError:
        server_offline_queue.put("SERVER_OFFLINE")


# this function get a username and checks if it is in the database through the server
def validate_new_chat(username_to_check):
    print("sending check to server")
    protocol.send(client_socket, f"CHECK_NEW_CHAT;{username_to_check}")


def validate_new_chat_group(username_to_check):
    print("sending check to server")
    protocol.send(client_socket, f"CHECK_NEW_CHAT_GROUP;{username_to_check}")


# this function closes the program when called
def close_program():
    client_socket.close()


def add_new_group_in_all(usernames, creator):
    for user in usernames:
        if user != creator:
            protocol.send(client_socket, f"ADD_NEW_GROUP_ALL;{user};{usernames}")
    protocol.send(client_socket, f"ADD_NEW_GROUP_TO_DATABASE;{usernames}")


def add_new_chat_in_all(user, user_to_add):
    protocol.send(client_socket, f"ADD_NEW_CHAT_ALL;{user};{user_to_add}")


# this function is for receiving messages from the server
def receive_message(client_socket, rsa_key):
    while True:
        try:
            # Acquire the lock before accessing a shared resource
            lock.acquire()
            if is_socket_open(client_socket):
                msg = protocol.receive(client_socket)
                message_header = msg.split(";", 1)[0]
                print(f"Received message header in receive_message function: {message_header}")
                if not msg:
                    print("[DISCONNECTED] Server disconnected.")
                    client_socket.close()
                    break

                elif msg.startswith("ADD_NEW_GROUP_ALL;"):
                    user = msg.split(";", 2)[1]
                    usernames = msg.split(";", 2)[2]
                    new_group_queue.put(usernames)

                elif msg.startswith("ADD_NEW_CHAT_ALL;"):
                    user = msg.split(";", 1)[1]
                    new_group_queue.put(user)

                elif msg.startswith("GET_PUBLIC_KEY;"):
                    public_key = msg.split(";", 1)[1]
                    public_key_queue.put(public_key)

                # user is offline
                elif msg == "USER_OFFLINE":
                    print("adding USER_OFFLINE to queue")
                    offline_queue.put("USER_OFFLINE")

                # user is online
                elif msg == "USER_ONLINE":
                    print("adding USER_ONLINE to queue")
                    offline_queue.put("USER_ONLINE")

                elif msg.startswith("CHECK_NEW_CHAT;"):
                    response = msg.split(';', 1)[1]
                    # put the response of the server in the queue
                    database_check_new_chat_queue.put(response)

                elif msg.startswith("CHECK_NEW_CHAT_GROUP;"):
                    response = msg.split(';', 1)[1]
                    # put the response of the server in the queue
                    database_check_new_chat_queue.put(response)

                elif msg.startswith("@;"):
                    msg = msg.split(";", 1)[1]
                    # to delete a chat
                    if msg.startswith("DELETE_CHAT;"):
                        user_to_delete = msg.split(";", 1)[1]
                        delete_chat_queue.put(user_to_delete)

                    # message is a file chunk
                    elif msg.startswith("FILE_CHUNK;"):
                        filename = msg.split(";", 4)[2]
                        chunk_data = msg.split(";", 4)[3]
                        recipient_username = msg.split(";", 4)[1]
                        chunk_hash = msg.split(";", 4)[4]

                        decrypted_chunk = decrypt_message(rsa_key, chunk_data)
                        decrypted_filename = decrypt_message(rsa_key, filename)

                        decrypted_chunk_str = decrypted_chunk.decode()
                        decrypted_filename_str = decrypted_filename.decode()

                        print(f"received chunk")
                        print(f"received filename")

                        temp_dir = r"C:\Users\Public"
                        base_filename = os.path.basename(decrypted_filename_str)
                        full_path = os.path.join(temp_dir, base_filename)

                        with open(full_path, 'ab') as file:
                            chunk = base64.b64decode(decrypted_chunk_str.encode())
                            # Write the file data to a file
                            file.write(chunk)
                        # Compute the SHA256 hash of the received chunk
                        hash_obj = hashlib.sha256()
                        hash_obj.update(chunk)
                        computed_hash = hash_obj.hexdigest()

                        # Compare the computed hash with the received hash
                        if computed_hash != chunk_hash:
                            print("Hash check failed. The chunk may not have arrived in full.")
                        else:
                            print("Hash check passed.")

                    # message is a photo chunk
                    elif msg.startswith("PHOTO_CHUNK;"):
                        filename = msg.split(";", 4)[2]
                        chunk_data = msg.split(";", 4)[3]
                        recipient_username = msg.split(";", 4)[1]
                        chunk_hash = msg.split(";", 4)[4]

                        decrypted_chunk = decrypt_message(rsa_key, chunk_data)
                        decrypted_filename = decrypt_message(rsa_key, filename)

                        decrypted_chunk_str = decrypted_chunk.decode()
                        decrypted_filename_str = decrypted_filename.decode()

                        print(f"received chunk")
                        print(f"received filename")

                        temp_dir = r"C:\Users\Public"
                        base_filename = os.path.basename(decrypted_filename_str)
                        full_path = os.path.join(temp_dir, base_filename)

                        with open(full_path, 'ab') as file:
                            chunk = base64.b64decode(decrypted_chunk_str.encode())
                            # Write the file data to a file
                            file.write(chunk)
                        # Compute the SHA256 hash of the received chunk
                        hash_obj = hashlib.sha256()
                        hash_obj.update(chunk)
                        computed_hash = hash_obj.hexdigest()

                        # Compare the computed hash with the received hash
                        if computed_hash != chunk_hash:
                            print("Hash check failed. The chunk may not have arrived in full.")
                        else:
                            print("Hash check passed.")

                    # message is a video chunk
                    elif msg.startswith("VIDEO_CHUNK;"):
                        filename = msg.split(";", 4)[2]
                        chunk_data = msg.split(";", 4)[3]
                        recipient_username = msg.split(";", 4)[1]
                        chunk_hash = msg.split(";", 4)[4]

                        decrypted_chunk = decrypt_message(rsa_key, chunk_data)
                        decrypted_filename = decrypt_message(rsa_key, filename)

                        decrypted_chunk_str = decrypted_chunk.decode()
                        decrypted_filename_str = decrypted_filename.decode()

                        print(f"received chunk")
                        print(f"received filename")

                        temp_dir = r"C:\Users\Public"
                        base_filename = os.path.basename(decrypted_filename_str)
                        full_path = os.path.join(temp_dir, base_filename)

                        with open(full_path, 'ab') as file:
                            chunk = base64.b64decode(decrypted_chunk_str.encode())
                            # Write the file data to a file
                            file.write(chunk)
                        # Compute the SHA256 hash of the received chunk
                        hash_obj = hashlib.sha256()
                        hash_obj.update(chunk)
                        computed_hash = hash_obj.hexdigest()

                        # Compare the computed hash with the received hash
                        if computed_hash != chunk_hash:
                            print("Hash check failed. The chunk may not have arrived in full.")
                        else:
                            print("Hash check passed.")

                    # message is an audio chunk
                    elif msg.startswith("AUDIO_CHUNK;"):
                        filename = msg.split(";", 4)[2]
                        chunk_data = msg.split(";", 4)[3]
                        recipient_username = msg.split(";", 4)[1]
                        chunk_hash = msg.split(";", 4)[4]

                        decrypted_chunk = decrypt_message(rsa_key, chunk_data)
                        decrypted_filename = decrypt_message(rsa_key, filename)

                        decrypted_chunk_str = decrypted_chunk.decode()
                        decrypted_filename_str = decrypted_filename.decode()

                        print(f"received chunk")
                        print(f"received filename")

                        temp_dir = r"C:\Users\Public"
                        base_filename = os.path.basename(decrypted_filename_str)
                        full_path = os.path.join(temp_dir, base_filename)

                        with open(full_path, 'ab') as file:
                            chunk = base64.b64decode(decrypted_chunk_str.encode())
                            # Write the file data to a file
                            file.write(chunk)
                        # Compute the SHA256 hash of the received chunk
                        hash_obj = hashlib.sha256()
                        hash_obj.update(chunk)
                        computed_hash = hash_obj.hexdigest()

                        # Compare the computed hash with the received hash
                        if computed_hash != chunk_hash:
                            print("Hash check failed. The chunk may not have arrived in full.")
                        else:
                            print("Hash check passed.")

                    # message is the end of file indicator
                    elif msg.startswith("END_OF_FILE;"):
                        sender_username = msg.split(";", 3)[1]
                        # Split the message into command and filename
                        recipient_username = msg.split(";", 3)[2]
                        filename = msg.split(";", 3)[3]

                        decrypted_message = decrypt_message(rsa_key, filename)
                        decrypted_message_str = decrypted_message.decode()

                        print(f"filename that is received in receive_message is: {decrypted_message_str}")
                        print("Received END_OF_FILE indicator in receive _message")
                        message_queue.put(f"{recipient_username};{sender_username};FILE: {decrypted_message_str}")

                    # message is the end of photo indicator
                    elif msg.startswith("END_OF_PHOTO;"):
                        sender_username = msg.split(";", 3)[1]
                        recipient_username = msg.split(";", 3)[2]
                        filename = msg.split(";", 3)[3]

                        decrypted_message = decrypt_message(rsa_key, filename)
                        decrypted_message_str = decrypted_message.decode()

                        print(f"filename that is received in receive_message is: {decrypted_message_str}")
                        print("Received END_OF_PHOTO indicator in receive _message")
                        message_queue.put(f"{recipient_username};{sender_username};PHOTO: {decrypted_message_str}")

                    # message is the end of video indicator
                    elif msg.startswith("END_OF_VIDEO;"):
                        sender_username = msg.split(";", 3)[1]
                        recipient_username = msg.split(";", 3)[2]
                        filename = msg.split(";", 3)[3]

                        decrypted_message = decrypt_message(rsa_key, filename)
                        decrypted_message_str = decrypted_message.decode()

                        print(f"filename that is received in receive_message is: {decrypted_message_str}")
                        print("Received END_OF_VIDEO indicator in receive _message")
                        message_queue.put(f"{recipient_username};{sender_username};VIDEO: {decrypted_message_str}")

                    # message is the end of audio indicator
                    elif msg.startswith("END_OF_AUDIO;"):
                        sender_username = msg.split(";", 3)[1]
                        recipient_username = msg.split(";", 3)[2]
                        filename = msg.split(";", 3)[3]

                        decrypted_message = decrypt_message(rsa_key, filename)
                        decrypted_message_str = decrypted_message.decode()

                        print(f"filename that is received in receive_message is: {decrypted_message_str}")
                        print("Received END_OF_AUDIO indicator in receive _message")
                        message_queue.put(f"{recipient_username};{sender_username};AUDIO: {decrypted_message_str}")

                    # message is a link
                    elif msg.startswith("LINK;"):
                        sender_username = msg.split(";", 3)[1]
                        recipient_username = msg.split(";", 3)[2]
                        link = msg.split(";", 3)[3]

                        decrypted_link = decrypt_message(rsa_key, link)

                        message_queue.put(f"{recipient_username};{sender_username};LINK: {decrypted_link.decode()}")

                    # message is a normal text message
                    elif msg.startswith("MESSAGE;"):
                        sender_username = msg.split(";", 3)[1]
                        recipient_username = msg.split(";", 3)[2]
                        message = msg.split(";", 3)[3]
                        print(f"received text message")

                        decrypted_message = decrypt_message(rsa_key, message)

                        message_queue.put(f"{recipient_username};{sender_username};MESSAGE: {decrypted_message.decode()}")

                elif msg.startswith("$"):

                    msg = msg.split(";", 1)[1]
                    # to delete a chat
                    if msg.startswith("DELETE_GROUP;"):
                        group_to_delete = msg.split(";", 1)[1]
                        delete_chat_queue.put(group_to_delete)

                    # message is a file chunk
                    elif msg.startswith("FILE_CHUNK;"):
                        filename = msg.split(";", 4)[2]
                        chunk_data = msg.split(";", 4)[3]
                        recipient_username = msg.split(";", 4)[1]
                        chunk_hash = msg.split(";", 4)[4]

                        decrypted_chunk = decrypt_message(rsa_key, chunk_data)
                        decrypted_filename = decrypt_message(rsa_key, filename)

                        decrypted_chunk_str = decrypted_chunk.decode()
                        decrypted_filename_str = decrypted_filename.decode()

                        print(f"received chunk")
                        print(f"received filename")

                        temp_dir = r"C:\Users\Public"
                        base_filename = os.path.basename(decrypted_filename_str)
                        full_path = os.path.join(temp_dir, base_filename)

                        with open(full_path, 'ab') as file:
                            chunk = base64.b64decode(decrypted_chunk_str.encode())
                            # Write the file data to a file
                            file.write(chunk)
                        # Compute the SHA256 hash of the received chunk
                        hash_obj = hashlib.sha256()
                        hash_obj.update(chunk)
                        computed_hash = hash_obj.hexdigest()

                        # Compare the computed hash with the received hash
                        if computed_hash != chunk_hash:
                            print("Hash check failed. The chunk may not have arrived in full.")
                        else:
                            print("Hash check passed.")

                    # message is a photo chunk
                    elif msg.startswith("PHOTO_CHUNK;"):
                        filename = msg.split(";", 4)[2]
                        chunk_data = msg.split(";", 4)[3]
                        recipient_username = msg.split(";", 4)[1]
                        chunk_hash = msg.split(";", 4)[4]

                        print(f"chunk length received is: {len(chunk_data)}")

                        decrypted_chunk = decrypt_message(rsa_key, chunk_data)
                        decrypted_filename = decrypt_message(rsa_key, filename)

                        decrypted_chunk_str = decrypted_chunk.decode()
                        decrypted_filename_str = decrypted_filename.decode()

                        print(f"received chunk")
                        print(f"received filename")

                        temp_dir = r"C:\Users\Public"
                        base_filename = os.path.basename(decrypted_filename_str)
                        full_path = os.path.join(temp_dir, base_filename)

                        with open(full_path, 'ab') as file:
                            chunk = base64.b64decode(decrypted_chunk_str.encode())
                            # Write the file data to a file
                            file.write(chunk)
                        # Compute the SHA256 hash of the received chunk
                        hash_obj = hashlib.sha256()
                        hash_obj.update(chunk)
                        computed_hash = hash_obj.hexdigest()

                        # Compare the computed hash with the received hash
                        if computed_hash != chunk_hash:
                            print("Hash check failed. The chunk may not have arrived in full.")
                        else:
                            print("Hash check passed.")

                    # message is a video chunk
                    elif msg.startswith("VIDEO_CHUNK;"):
                        filename = msg.split(";", 4)[2]
                        chunk_data = msg.split(";", 4)[3]
                        recipient_username = msg.split(";", 4)[1]
                        chunk_hash = msg.split(";", 4)[4]

                        decrypted_chunk = decrypt_message(rsa_key, chunk_data)
                        decrypted_filename = decrypt_message(rsa_key, filename)

                        decrypted_chunk_str = decrypted_chunk.decode()
                        decrypted_filename_str = decrypted_filename.decode()

                        print(f"received chunk")
                        print(f"received filename")

                        temp_dir = r"C:\Users\Public"
                        base_filename = os.path.basename(decrypted_filename_str)
                        full_path = os.path.join(temp_dir, base_filename)

                        with open(full_path, 'ab') as file:
                            chunk = base64.b64decode(decrypted_chunk_str.encode())
                            # Write the file data to a file
                            file.write(chunk)
                        # Compute the SHA256 hash of the received chunk
                        hash_obj = hashlib.sha256()
                        hash_obj.update(chunk)
                        computed_hash = hash_obj.hexdigest()

                        # Compare the computed hash with the received hash
                        if computed_hash != chunk_hash:
                            print("Hash check failed. The chunk may not have arrived in full.")
                        else:
                            print("Hash check passed.")

                    # message is an audio chunk
                    elif msg.startswith("AUDIO_CHUNK;"):
                        filename = msg.split(";", 4)[2]
                        chunk_data = msg.split(";", 4)[3]
                        recipient_username = msg.split(";", 4)[1]
                        chunk_hash = msg.split(";", 4)[4]

                        decrypted_chunk = decrypt_message(rsa_key, chunk_data)
                        decrypted_filename = decrypt_message(rsa_key, filename)

                        decrypted_chunk_str = decrypted_chunk.decode()
                        decrypted_filename_str = decrypted_filename.decode()

                        print(f"received chunk")
                        print(f"received filename")

                        temp_dir = r"C:\Users\Public"
                        base_filename = os.path.basename(decrypted_filename_str)
                        full_path = os.path.join(temp_dir, base_filename)

                        with open(full_path, 'ab') as file:
                            chunk = base64.b64decode(decrypted_chunk_str.encode())
                            # Write the file data to a file
                            file.write(chunk)
                        # Compute the SHA256 hash of the received chunk
                        hash_obj = hashlib.sha256()
                        hash_obj.update(chunk)
                        computed_hash = hash_obj.hexdigest()

                        # Compare the computed hash with the received hash
                        if computed_hash != chunk_hash:
                            print("Hash check failed. The chunk may not have arrived in full.")
                        else:
                            print("Hash check passed.")

                    # message is the end of file indicator
                    elif msg.startswith("END_OF_FILE;"):
                        chat_name = msg.split(";", 4)[1]
                        sender_username = msg.split(";", 4)[2]
                        recipient_username = msg.split(";", 4)[3]
                        filename = msg.split(";", 4)[4]

                        decrypted_message = decrypt_message(rsa_key, filename)
                        decrypted_message_str = decrypted_message.decode()

                        print(f"filename that is received in receive_message is: {decrypted_message_str}")
                        print("Received END_OF_FILE indicator in receive_message")
                        message_queue.put(f"{sender_username};{chat_name};FILE: {decrypted_message_str}")

                    # message is the end of photo indicator
                    elif msg.startswith("END_OF_PHOTO;"):
                        chat_name = msg.split(";", 4)[1]
                        sender_username = msg.split(";", 4)[2]
                        recipient_username = msg.split(";", 4)[3]
                        filename = msg.split(";", 4)[4]

                        decrypted_message = decrypt_message(rsa_key, filename)
                        decrypted_message_str = decrypted_message.decode()

                        print(f"filename that is received in receive_message is: {decrypted_message_str}")
                        print("Received END_OF_PHOTO indicator in receive _message")
                        message_queue.put(f"{sender_username};{chat_name};PHOTO: {decrypted_message_str}")

                    # message is the end of video indicator
                    elif msg.startswith("END_OF_VIDEO;"):
                        chat_name = msg.split(";", 4)[1]
                        sender_username = msg.split(";", 4)[2]
                        recipient_username = msg.split(";", 4)[3]
                        filename = msg.split(";", 4)[4]

                        decrypted_message = decrypt_message(rsa_key, filename)
                        decrypted_message_str = decrypted_message.decode()

                        print(f"filename that is received in receive_message is: {decrypted_message_str}")
                        print("Received END_OF_VIDEO indicator in receive _message")
                        message_queue.put(f"{sender_username};{chat_name};VIDEO: {decrypted_message_str}")

                    # message is the end of audio indicator
                    elif msg.startswith("END_OF_AUDIO;"):
                        chat_name = msg.split(";", 4)[1]
                        sender_username = msg.split(";", 4)[2]
                        recipient_username = msg.split(";", 4)[3]
                        filename = msg.split(";", 4)[4]

                        decrypted_message = decrypt_message(rsa_key, filename)
                        decrypted_message_str = decrypted_message.decode()

                        print(f"filename that is received in receive_message is: {decrypted_message_str}")
                        print("Received END_OF_AUDIO indicator in receive _message")
                        message_queue.put(f"{sender_username};{chat_name};AUDIO: {decrypted_message_str}")
                        # message_queue.put(f"{sender_username};{chat_name};AUDIO: {filename}")

                    # message is a link
                    elif msg.startswith("LINK;"):
                        chat_name = msg.split(";", 4)[1]
                        sender_username = msg.split(";", 4)[2]
                        recipient_username = msg.split(";", 4)[3]
                        link = msg.split(";", 4)[4]

                        decrypted_link = decrypt_message(rsa_key, link)

                        message_queue.put(f"{sender_username};{chat_name};LINK: {decrypted_link.decode()}")

                    # message is a normal text message
                    elif msg.startswith("MESSAGE;"):
                        chat_name = msg.split(";", 4)[1]
                        sender_username = msg.split(";", 4)[2]
                        recipient_username = msg.split(";", 4)[3]
                        message = msg.split(";", 4)[4]
                        print(f"received text message")

                        decrypted_message = decrypt_message(rsa_key, message)

                        message_queue.put(f"{sender_username};{chat_name};MESSAGE: {decrypted_message.decode()}")

            else:
                print("The socket is closed.")
                break

        except socket.timeout:
            print("[ERROR] Socket operation timed out.")
            break

        except Exception as e:
            import traceback
            print(f"[ERROR] Exception: {str(e)}")
            traceback.print_exc()
            print("[ERROR] Failed to receive message.")
            client_socket.close()
            break
        finally:
            # Release the lock after the shared resource is updated
            lock.release()


# function that gets a message and a recipient username and sends to the server the message with the recipient username
def send_message(msg, recipient_username):
    global client_socket
    filename = ""
    if msg != "":
        try:
            # Disable Nagle's algorithm
            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            if msg.startswith("@"):
                msg = msg.split(";", 1)[1]
                # for deleting a chat
                if msg.startswith("DELETE_CHAT;"):
                    user_to_delete = msg.split(";", 2)[1]
                    current_user = msg.split(";", 2)[2]
                    protocol.send(client_socket, f"DELETE_CHAT;{user_to_delete};{current_user}")

                # the message that is sent when a client sends any kind of message to check if the recipient is online
                elif msg.startswith("MESSAGE_CHECK;"):
                    username = msg.split(";", 1)[1]
                    protocol.send(client_socket, f"@{recipient_username} MESSAGE_CHECK;{username}")

                # message is a file chunk
                elif msg.startswith("FILE_CHUNK;"):
                    # Split the message into command and file name
                    filename = msg.split(";", 4)[1]
                    chunk = msg.split(";", 4)[2]
                    username = msg.split(";", 4)[3]
                    chunk_hash = msg.split(";", 4)[4]

                    # encrypt with the public keys of the sender and recipient
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{recipient_username}")
                    response_receiver_chunk = public_key_queue.get()
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{recipient_username}")
                    response_receiver = public_key_queue.get()

                    chunk_encrypted_receiver = encrypt_message(chunk, response_receiver_chunk)
                    filename_encrypted_receiver = encrypt_message(filename, response_receiver)

                    print(f"sending chunk in send_message")
                    print(f"sending filename in send_message")
                    # Send the chunk
                    protocol.send(client_socket, f"@{recipient_username} FILE_CHUNK;{filename_encrypted_receiver};{chunk_encrypted_receiver};{chunk_hash}")

                # message is a photo chunk
                elif msg.startswith("PHOTO_CHUNK;"):
                    # Split the message into command and file name
                    filename = msg.split(";", 4)[1]
                    chunk = msg.split(";", 4)[2]
                    username = msg.split(";", 4)[3]
                    chunk_hash = msg.split(";", 4)[4]

                    # encrypt with the public keys of the sender and recipient
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{recipient_username}")
                    response_receiver_chunk = public_key_queue.get()
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{recipient_username}")
                    response_receiver = public_key_queue.get()

                    chunk_encrypted_receiver = encrypt_message(chunk, response_receiver_chunk)
                    filename_encrypted_receiver = encrypt_message(filename, response_receiver)

                    print(f"sending chunk in send_message")
                    print(f"sending filename in send_message")
                    # Send the chunk
                    protocol.send(client_socket, f"@{recipient_username} PHOTO_CHUNK;{filename_encrypted_receiver};{chunk_encrypted_receiver};{chunk_hash}")

                # message is a video chunk
                elif msg.startswith("VIDEO_CHUNK;"):
                    # Split the message into command and file name
                    filename = msg.split(";", 4)[1]
                    chunk = msg.split(";", 4)[2]
                    username = msg.split(";", 4)[3]
                    chunk_hash = msg.split(";", 4)[4]

                    # encrypt with the public keys of the sender and recipient
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{recipient_username}")
                    response_receiver_chunk = public_key_queue.get()
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{recipient_username}")
                    response_receiver = public_key_queue.get()

                    chunk_encrypted_receiver = encrypt_message(chunk, response_receiver_chunk)
                    filename_encrypted_receiver = encrypt_message(filename, response_receiver)

                    print(f"sending chunk in send_message")
                    print(f"sending filename in send_message")
                    # Send the chunk
                    protocol.send(client_socket, f"@{recipient_username} VIDEO_CHUNK;{filename_encrypted_receiver};{chunk_encrypted_receiver};{chunk_hash}")

                # message is an audio chunk
                elif msg.startswith("AUDIO_CHUNK;"):
                    # Split the message into command and file name
                    filename = msg.split(";", 4)[1]
                    chunk = msg.split(";", 4)[2]
                    username = msg.split(";", 4)[3]
                    chunk_hash = msg.split(";", 4)[4]

                    # encrypt with the public keys of the sender and recipient
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{recipient_username}")
                    response_receiver_chunk = public_key_queue.get()
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{recipient_username}")
                    response_receiver = public_key_queue.get()

                    chunk_encrypted_receiver = encrypt_message(chunk, response_receiver_chunk)
                    filename_encrypted_receiver = encrypt_message(filename, response_receiver)

                    print(f"sending chunk in send_message")
                    print(f"sending filename in send_message")
                    # Send the chunk
                    protocol.send(client_socket, f"@{recipient_username} AUDIO_CHUNK;{filename_encrypted_receiver};{chunk_encrypted_receiver};{chunk_hash}")

                # message is the end of file indicator
                elif msg.startswith("END_OF_FILE;"):
                    # Split the message into command and file name
                    filename = msg.split(";", 2)[1]
                    username = msg.split(";", 2)[2]

                    # encrypt with the public keys of the sender and recipient
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{recipient_username}")
                    response_receiver = public_key_queue.get()
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{username}")
                    response_sender = public_key_queue.get()

                    message_encrypted_receiver = encrypt_message(filename, response_receiver)
                    message_encrypted_sender = encrypt_message(filename, response_sender)

                    print(f"sending end fo file indicator in send_message. filename is: {filename}")
                    # Send the end of file indicator
                    protocol.send(client_socket, f"@{recipient_username} END_OF_FILE;{message_encrypted_receiver};{message_encrypted_sender}")

                # message is the end of photo indicator
                elif msg.startswith("END_OF_PHOTO;"):
                    # Split the message into command and file name
                    filename = msg.split(";", 2)[1]
                    username = msg.split(";", 2)[2]

                    # encrypt with the public keys of the sender and recipient
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{recipient_username}")
                    response_receiver = public_key_queue.get()
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{username}")
                    response_sender = public_key_queue.get()

                    message_encrypted_receiver = encrypt_message(filename, response_receiver)
                    message_encrypted_sender = encrypt_message(filename, response_sender)

                    print(f"sending end fo photo indicator in send_message. filename is: {filename}")
                    # Send the end of file indicator
                    protocol.send(client_socket, f"@{recipient_username} END_OF_PHOTO;{message_encrypted_receiver};{message_encrypted_sender}")

                # message is the end of video indicator
                elif msg.startswith("END_OF_VIDEO;"):
                    # Split the message into command and file name
                    filename = msg.split(";", 2)[1]
                    username = msg.split(";", 2)[2]

                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{recipient_username}")
                    response_receiver = public_key_queue.get()
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{username}")
                    response_sender = public_key_queue.get()

                    message_encrypted_receiver = encrypt_message(filename, response_receiver)
                    message_encrypted_sender = encrypt_message(filename, response_sender)

                    # encrypt with the public keys of the sender and recipient
                    print(f"sending end of video indicator in send_message. filename is: {filename}")
                    # Send the end of file indicator
                    protocol.send(client_socket, f"@{recipient_username} END_OF_VIDEO;{message_encrypted_receiver};{message_encrypted_sender}")

                # message is the end of audio indicator
                elif msg.startswith("END_OF_AUDIO;"):
                    # Split the message into command and file name
                    filename = msg.split(";", 2)[1]
                    username = msg.split(";", 2)[2]

                    # encrypt with the public keys of the sender and recipient
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{recipient_username}")
                    response_receiver = public_key_queue.get()
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{username}")
                    response_sender = public_key_queue.get()

                    message_encrypted_receiver = encrypt_message(filename, response_receiver)
                    message_encrypted_sender = encrypt_message(filename, response_sender)

                    print(f"sending end fo audio indicator in send_message. filename is: {filename}")
                    # Send the end of file indicator
                    protocol.send(client_socket, f"@{recipient_username} END_OF_AUDIO;{message_encrypted_receiver};{message_encrypted_sender}")

                # message is a link
                elif msg.startswith("LINK;"):
                    # Split the message into command and link name
                    link_url = msg.split(";", 2)[1]
                    username = msg.split(";", 2)[2]

                    # encrypt with the public keys of the sender and recipient
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{recipient_username}")
                    response_receiver = public_key_queue.get()
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{username}")
                    response_sender = public_key_queue.get()

                    message_encrypted_receiver = encrypt_message(link_url, response_receiver)
                    message_encrypted_sender = encrypt_message(link_url, response_sender)

                    protocol.send(client_socket, f"@{recipient_username} LINK;{message_encrypted_receiver};{message_encrypted_sender}")

                # message is a normal text message
                elif msg.startswith("MESSAGE;"):
                    message = msg.split(";", 2)[1]
                    username = msg.split(";", 2)[2]

                    # encrypt with the public keys of the sender and recipient
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{recipient_username}")
                    response_receiver = public_key_queue.get()
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{username}")
                    response_sender = public_key_queue.get()

                    message_encrypted_receiver = encrypt_message(message, response_receiver)
                    message_encrypted_sender = encrypt_message(message, response_sender)

                    # Send the encrypted AES key, IV, and message to the server
                    protocol.send(client_socket, f"@{recipient_username} MESSAGE;{message_encrypted_receiver};{message_encrypted_sender}")

                # message is to save the file in the recipient end
                elif msg.startswith("SAVED_FILE;"):
                    print("sending saved_file to server")

                    sender_username = msg.split(";", 5)[1]
                    receiver_username = msg.split(";", 5)[2]
                    time_sent = msg.split(";", 5)[3]
                    type_file = msg.split(";", 5)[4]
                    new_path = msg.split(";", 5)[5]
                    print(f"sender username is: {sender_username}")
                    print(f"receiver username is: {receiver_username}")
                    # encrypt with the public key of the sender
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{sender_username}")
                    response_sender_new_path = public_key_queue.get()

                    new_path_encrypted = encrypt_message(new_path, response_sender_new_path)
                    print(new_path)
                    protocol.send(client_socket, f"SAVED_FILE;{sender_username};{receiver_username};{time_sent};{type_file};{new_path_encrypted}")

            elif msg.startswith("$"):
                msg = msg.split(";", 1)[1]
                users = recipient_username.replace("Group Chat ", "")
                list_of_users = users.split(', ')

                for user in list_of_users:
                    # the message that is sent when a client sends any kind of message to check if the recipient is online
                    if msg.startswith("MESSAGE_CHECK;"):
                        username = msg.split(";", 1)[1]
                        if user != username:
                            protocol.send(client_socket, f"${user} MESSAGE_CHECK;{username}")

                    elif msg.startswith("DELETE_GROUP;"):
                        username = msg.split(";", 2)[1]
                        selected_chat = msg.split(";", 2)[2]

                        if username != user:
                            protocol.send(client_socket, f"${user} DELETE_GROUP;{selected_chat}")

                    # message is a file chunk
                    elif msg.startswith("FILE_CHUNK;"):
                        # Split the message into command and file name
                        filename = msg.split(";", 4)[1]
                        chunk = msg.split(";", 4)[2]
                        username = msg.split(";", 4)[3]
                        chunk_hash = msg.split(";", 4)[4]
                        if user != username:

                            # encrypt with the public keys of the sender and recipient
                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{user}")
                            response_receiver_chunk = public_key_queue.get()

                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{user}")
                            response_receiver = public_key_queue.get()

                            chunk_encrypted_receiver = encrypt_message(chunk, response_receiver_chunk)
                            filename_encrypted_receiver = encrypt_message(filename, response_receiver)

                            print(f"sending chunk in send_message")
                            print(f"sending filename in send_message")
                            # Send the chunk
                            protocol.send(client_socket, f"${user} FILE_CHUNK;{filename_encrypted_receiver};{chunk_encrypted_receiver};{chunk_hash}")

                    # message is a photo chunk
                    elif msg.startswith("PHOTO_CHUNK;"):
                        # Split the message into command and file name
                        filename = msg.split(";", 4)[1]
                        chunk = msg.split(";", 4)[2]
                        username = msg.split(";", 4)[3]
                        chunk_hash = msg.split(";", 4)[4]
                        if user != username:
                            # encrypt with the public keys of the sender and recipient
                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{user}")
                            response_receiver_chunk = public_key_queue.get()

                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{user}")
                            response_receiver = public_key_queue.get()

                            chunk_encrypted_receiver = encrypt_message(chunk, response_receiver_chunk)
                            filename_encrypted_receiver = encrypt_message(filename, response_receiver)
                            print(f"sending chunk in send_message")
                            print(f"sending filename in send_message")
                            # Send the chunk
                            protocol.send(client_socket, f"${user} PHOTO_CHUNK;{filename_encrypted_receiver};{chunk_encrypted_receiver};{chunk_hash}")

                    # message is a video chunk
                    elif msg.startswith("VIDEO_CHUNK;"):
                        # Split the message into command and file name
                        filename = msg.split(";", 4)[1]
                        chunk = msg.split(";", 4)[2]
                        username = msg.split(";", 4)[3]
                        chunk_hash = msg.split(";", 4)[4]
                        if user != username:

                            # encrypt with the public keys of the sender and recipient
                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{user}")
                            response_receiver_chunk = public_key_queue.get()

                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{user}")
                            response_receiver = public_key_queue.get()

                            chunk_encrypted_receiver = encrypt_message(chunk, response_receiver_chunk)
                            filename_encrypted_receiver = encrypt_message(filename, response_receiver)

                            print(f"sending chunk in send_message")
                            print(f"sending filename in send_message")
                            # Send the chunk
                            protocol.send(client_socket, f"${user} VIDEO_CHUNK;{filename_encrypted_receiver};{chunk_encrypted_receiver};{chunk_hash}")

                    # message is an audio chunk
                    elif msg.startswith("AUDIO_CHUNK;"):
                        # Split the message into command and file name
                        filename = msg.split(";", 4)[1]
                        chunk = msg.split(";", 4)[2]
                        username = msg.split(";", 4)[3]
                        chunk_hash = msg.split(";", 4)[4]
                        if user != username:

                            # encrypt with the public keys of the sender and recipient
                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{user}")
                            response_receiver_chunk = public_key_queue.get()

                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{user}")
                            response_receiver = public_key_queue.get()

                            chunk_encrypted_receiver = encrypt_message(chunk, response_receiver_chunk)
                            filename_encrypted_receiver = encrypt_message(filename, response_receiver)

                            print(f"sending chunk in send_message")
                            print(f"sending filename in send_message")
                            # Send the chunk
                            protocol.send(client_socket,  f"${user} AUDIO_CHUNK;{filename_encrypted_receiver};{chunk_encrypted_receiver};{chunk_hash}")

                    # message is the end of file indicator
                    elif msg.startswith("END_OF_FILE;"):
                        # Split the message into command and file name
                        filename = msg.split(";", 2)[1]
                        username = msg.split(";", 2)[2]
                        if user != username:

                            # encrypt with the public keys of the sender and recipient
                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{user}")
                            response_receiver = public_key_queue.get()

                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{username}")
                            response_sender = public_key_queue.get()

                            message_encrypted_receiver = encrypt_message(filename, response_receiver)
                            message_encrypted_sender = encrypt_message(filename, response_sender)

                            print(f"sending end fo file indicator in send_message. filename is: {filename}")
                            # Send the end of file indicator
                            protocol.send(client_socket, f"${user} END_OF_FILE;{message_encrypted_receiver};{message_encrypted_sender};{recipient_username}")

                    # message is the end of photo indicator
                    elif msg.startswith("END_OF_PHOTO;"):
                        # Split the message into command and file name
                        filename = msg.split(";", 2)[1]
                        username = msg.split(";", 2)[2]
                        if user != username:

                            # encrypt with the public keys of the sender and recipient
                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{user}")
                            response_receiver = public_key_queue.get()
                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{username}")
                            response_sender = public_key_queue.get()

                            message_encrypted_receiver = encrypt_message(filename, response_receiver)
                            message_encrypted_sender = encrypt_message(filename, response_sender)

                            print(f"sending end fo photo indicator in send_message. filename is: {filename}")
                            # Send the end of file indicator
                            protocol.send(client_socket, f"${user} END_OF_PHOTO;{message_encrypted_receiver};{message_encrypted_sender};{recipient_username}")

                    # message is the end of video indicator
                    elif msg.startswith("END_OF_VIDEO;"):
                        # Split the message into command and file name
                        filename = msg.split(";", 2)[1]
                        username = msg.split(";", 2)[2]
                        if user != username:

                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{user}")
                            response_receiver = public_key_queue.get()
                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{username}")
                            response_sender = public_key_queue.get()

                            message_encrypted_receiver = encrypt_message(filename, response_receiver)
                            message_encrypted_sender = encrypt_message(filename, response_sender)

                            # encrypt with the public keys of the sender and recipient
                            print(f"sending end of video indicator in send_message. filename is: {filename}")
                            # Send the end of file indicator
                            protocol.send(client_socket, f"${user} END_OF_VIDEO;{message_encrypted_receiver};{message_encrypted_sender};{recipient_username}")

                    # message is the end of audio indicator
                    elif msg.startswith("END_OF_AUDIO;"):
                        # Split the message into command and file name
                        filename = msg.split(";", 2)[1]
                        username = msg.split(";", 2)[2]
                        if user != username:

                            # encrypt with the public keys of the sender and recipient
                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{user}")
                            response_receiver = public_key_queue.get()
                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{username}")
                            response_sender = public_key_queue.get()

                            message_encrypted_receiver = encrypt_message(filename, response_receiver)
                            message_encrypted_sender = encrypt_message(filename, response_sender)

                            print(f"sending end fo audio indicator in send_message. filename is: {filename}")
                            # Send the end of file indicator
                            protocol.send(client_socket, f"${user} END_OF_AUDIO;{message_encrypted_receiver};{message_encrypted_sender};{recipient_username}")

                    # message is a link
                    elif msg.startswith("LINK;"):
                        # Split the message into command and link name
                        link_url = msg.split(";", 2)[1]
                        username = msg.split(";", 2)[2]
                        if user != username:

                            # encrypt with the public keys of the sender and recipient
                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{user}")
                            response_receiver = public_key_queue.get()
                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{username}")
                            response_sender = public_key_queue.get()

                            message_encrypted_receiver = encrypt_message(link_url, response_receiver)
                            message_encrypted_sender = encrypt_message(link_url, response_sender)

                            protocol.send(client_socket, f"${user} LINK;{message_encrypted_receiver};{message_encrypted_sender};{recipient_username}")

                    # message is a normal text message
                    elif msg.startswith("MESSAGE;"):
                        message = msg.split(";", 2)[1]
                        username = msg.split(";", 2)[2]
                        if user != username:
                            # encrypt with the public keys of the sender and recipient
                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{user}")
                            response_receiver = public_key_queue.get()
                            protocol.send(client_socket, f"GET_PUBLIC_KEY;{username}")
                            response_sender = public_key_queue.get()

                            message_encrypted_receiver = encrypt_message(message, response_receiver)
                            message_encrypted_sender = encrypt_message(message, response_sender)

                            # Send the encrypted AES key, IV, and message to the server
                            protocol.send(client_socket, f"${user} MESSAGE;{message_encrypted_receiver};{message_encrypted_sender};{recipient_username}")
                        else:
                            print("user is username")

        except socket.error as e:
            if e.errno == 10038:  # This is the error number corresponding to WinError 10038
                print("An operation was attempted on something that is not a socket. Exiting...")
                messagebox.showinfo("Error", f"The server is not running. Exiting")
                os._exit(0)

        except Exception as e:
            print("[ERROR] Failed to send message.")
            # Print the exception information
            print(f"Exception: {str(e)}")
            import traceback
            traceback.print_exc()


# this function get a username and starts the connection of the server
def main(username, identifier):
    global client_socket
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))
        server_offline_queue.put("SERVER_ONLINE")
        print("sent server online")

        rsa_key = None
        rsa_public_key = None

        if identifier == "SIGN_UP":
            # Generate RSA keys
            rsa_key, rsa_public_key = generate_rsa_keys()

            # Save the private key
            with open(f"C:\\Users\\Public\\{username}_private.pem", "wb") as f:
                f.write(rsa_key.export_key())

            # Encrypt the private key file
            key = os.urandom(16)  # Use a secure method to generate and store this key
            # Convert the key to a hexadecimal string
            key_hex = key.hex()
            # Store the key
            keyring.set_password("myapplication", username, key_hex)

            encrypt_file(f"C:\\Users\\Public\\{username}_private.pem", key)

            # Save the public key
            with open(f"C:\\Users\\Public\\{username}_public.pem", "wb") as f:
                f.write(rsa_public_key.export_key())

        elif identifier == "LOG_IN":
            # Retrieve the key
            key_hex = keyring.get_password("myapplication", username)
            key = bytes.fromhex(key_hex)
            decrypt_file(f"C:\\Users\\Public\\{username}_private.pem", key)

            # Load the private key
            with open(f"C:\\Users\\Public\\{username}_private.pem", "rb") as f:
                rsa_key = RSA.import_key(f.read())
            # Encrypt the private key file again
            encrypt_file(f"C:\\Users\\Public\\{username}_private.pem", key)

            # Load the public key
            with open(f"C:\\Users\\Public\\{username}_public.pem", "rb") as f:
                rsa_public_key = RSA.import_key(f.read())

        rsa_public_key_pem = rsa_public_key.export_key().decode()
        # send to the server the new user to add to the active users dictionary
        protocol.send(client_socket, f"ADD_NEW_USERNAME;{username};{rsa_public_key_pem}")
        print(f"sent username to add to the server in client: {username}")

        # start the thread for receiving messages
        receive_thread = threading.Thread(target=receive_message, args=(client_socket, rsa_key))
        receive_thread.start()

    except ConnectionRefusedError:
        server_offline_queue.put("SERVER_OFFLINE")


if __name__ == "__main__":
    main()
