# import socket
# import hashlib
# import os
# import json
# import ssl
#
# IP_ADD = '127.0.0.1'
# PORT = 9999
#
# # create sockets and get connection from client
# server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server_socket.bind(('127.0.0.1', PORT))
# server_socket.listen(1)
# (client_socket, address) = server_socket.accept()
# print("client connected")
# while True:
#     # rawdata = client_socket.recv(1024).decode()
#     data = client_socket.recv(1024).decode()
#     print(data) # prints json format
#     # data = json.loads(rawdata)  # data is a  dictionary created from json
#     # data = (client_socket.recv(1024).decode()).split(',')
#     print(data)  #print python dict
#     op, username, password = data.split(',')
#
#     if op == "s":
#         print("s")
#         # next 3 lines are instead of the DB
#         salt = os.urandom(2048)  # creates salt for the user
#         print(salt)  # 2048 bytes
#         print(list(salt))
#         hashed_pass = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
#         # Store in DB:  username, salt, hashed_pass
#         print("encrypted")
#         data_to_send = ('registration accepted'.encode())
#     elif op == "l":
#         # go to DB - see if username exists, if yes, fetch salt & hashed_pass
#         hashed_request_pass = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
#         if (username == username) and (hashed_request_pass == hashed_pass):
#             # compare to DB:  data['username'] to DB:username, hashed_request_pass to DB:hashed_pass
#             data_to_send = ('Hello  ' + username).encode()
#         else:
#             data_to_send = 'Wrong details'.encode()
#     else:
#         break
#     client_socket.send(data_to_send)
#
#
# client_socket.close()
# server_socket.close()


import socket
import protocol


public_keys = {}


# Create a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)
print("Server: Listening for connections...")
client_socket, client_address = server_socket.accept()
print(f"Server: Accepted connection from {client_address}")


while True:
    # Receive the encrypted AES key, IV, and message from the client
    data = protocol.receive(client_socket)
    print(data)
    if data.startswith("ADD_PUBLIC_KEY;"):
        print("ADD_PUBLIC_KEY")

        public_key = data.split(";", 1)[1]
        public_keys[1] = public_key
        print(public_keys)
        protocol.send(client_socket, f"ADDED_PUBLIC_KEY")

    elif data.startswith("GET_PUBLIC_KEY"):
        print("GET_PUBLIC_KEY")

        public_key = public_keys[1]
        protocol.send(client_socket, f"PUBLIC_KEY;{public_key}")

    elif data.startswith("MESSAGE;"):
        print(f"Server: Encrypted data received from client: {data}")

        # Forward the encrypted AES key, IV, and message to the client
        protocol.send(client_socket, data)
        print("Server: Encrypted data forwarded to client")

    elif data == "no msg":
        client_socket.close()
        break
