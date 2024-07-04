import os
import socket
import protocol
import threading
import database
import hashlib
import re


# IP address
HOST = "192.168.1.182"

# port
PORT = 9999
# the max client we can handle
MAX_CLIENTS = 3

# dictionary to store the client sockets and their identifiers
clients = {}
# dictionary to store the public_keys and their identifiers
public_keys = {}

database.create_database()

recipient_socket = None

COMMON_PASSWORDS = {"123456", "password", "123456789", "12345678", "12345", "1234567", "qwerty", "abc123", "password1", "admin"}

# Create a lock
lock = threading.Lock()


# this function gets a username and a password to check, and it checks the strength of the password, by the requirements specified below
def validate_password(username, password):
    # - At least one uppercase letter
    # - At least one lowercase letter
    # - At least one digit
    # - At least 8 characters long
    # - No prohibited characters: ; | , ' " \
    # - No spaces
    # - Not a common password
    # - Not similar to username
    # - No sequences of three or more repeated characters
    # - No prohibited characters: ; | , ' " \ in the username
    # - name is not None

    if len(password) < 8:
        return "Password must be at least 8 characters long."

    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter."

    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter."

    if not re.search(r'\d', password):
        return "Password must contain at least one digit."

    if re.search(r'[;|,\'"\\]', password):
        return "Password must not contain any of the following characters: ; | , ' \" \\"

    if re.search(r'\s', password):
        return "Password must not contain spaces."

    if password.lower() in COMMON_PASSWORDS:
        return "Password is too common. Please choose a stronger password."

    if username.lower() in password.lower():
        return "Password should not contain your username."

    if re.search(r'(.)\1{2,}', password):
        return "Password must not contain sequences of three or more repeated characters."

    if re.search(r'[;|,\'"\\]', username):
        return "Username must not contain any of the following characters: ; | , ' \" \\"

    if username == "None":
        return "Username must not be None"

    return None  # Password is valid


# this function get a client socket and the client address and handles received message according to its type and sends the appropriate response
def handle_client(client_socket, client_address):
    print(f"[NEW CONNECTION] {client_address} connected.")
    recipient_socket = None
    username = None
    while True:
        try:
            # receive the message
            msg = protocol.receive(client_socket)
            print(msg)
            if not msg:
                print(f"[NEW CONNECTION] {client_address} disconnected.")
                print(f"Removing {username} from clients")
                del clients[username]
                del public_keys[username]
                client_socket.close()
                break
            elif msg == "no msg":
                break

            elif msg.startswith("ADD_NEW_GROUP_ALL;"):
                user = msg.split(";", 2)[1]
                usernames = msg.split(";", 2)[2]
                group_members = usernames.replace("'", "").replace("[", "").replace("]", "")
                list_of_users = group_members.split(', ')
                if user in clients:
                    user_socket = clients[user]
                    protocol.send(user_socket, f"ADD_NEW_GROUP_ALL;{user};{usernames}")

            elif msg.startswith("ADD_NEW_GROUP_TO_DATABASE;"):
                usernames = msg.split(";", 1)[1]
                group_members = usernames.replace("'", "").replace("[", "").replace("]", "")
                list_of_users = group_members.split(', ')
                user1 = list_of_users[0]
                user2 = list_of_users[1]
                user3 = "None"
                user4 = "None"
                user5 = "None"
                len_list = len(list_of_users)
                if len_list >= 3:
                    user3 = list_of_users[2]
                if len_list >= 4:
                    user4 = list_of_users[3]
                if len_list >= 5:
                    user5 = list_of_users[4]
                database.add_group(user1, user2, user3, user4, user5)

            elif msg.startswith("ADD_NEW_CHAT_ALL;"):
                user = msg.split(";", 2)[1]
                user_to_add = msg.split(";", 2)[2]
                user_socket = clients[user]
                protocol.send(user_socket, f"ADD_NEW_CHAT_ALL;{user_to_add}")
                database.add_chat(user, user_to_add)

            elif msg.startswith("GET_PUBLIC_KEY"):
                username_to_add = msg.split(";", 2)[1]
                if username_to_add in clients and username_to_add in public_keys:
                    public_key = public_keys[username_to_add]
                    print(f"sending public key")
                    protocol.send(client_socket, f"GET_PUBLIC_KEY;{public_key}")
                else:
                    print(f"User {username_to_add} not found. in GET_PUBLIC_KEY")

            # message is to add a username
            elif msg.startswith('ADD_NEW_USERNAME;'):
                username_to_add_to_dictionary = msg.split(';', 2)[1]
                public_key = msg.split(';', 2)[2]

                # check if username already exists
                if username_to_add_to_dictionary in clients.keys():
                    print("username is in the dictionary")
                else:
                    print(f"added username to dictionary: {username_to_add_to_dictionary}")
                    # add the new username to the clients dictionary
                    clients[username_to_add_to_dictionary] = client_socket
                    public_keys[username_to_add_to_dictionary] = public_key
                    username = username_to_add_to_dictionary

            # message is to check the client in the database, and do a login or sign up, and send the message and chat history
            elif msg.startswith('CHECK_CLIENT_IN_DATABASE;'):
                username_to_check_in_database = msg.split(';', 3)[1]
                password_to_check_in_database = msg.split(';', 3)[2]
                identifier = msg.split(';', 3)[3]

                client_ip, client_port = client_address
                if identifier == "LOG_IN":
                    if database.user_exists(username_to_check_in_database):
                        salt, hashed_password = database.get_salt_and_hashed_password(username_to_check_in_database)
                        hashed_request_pass = hashlib.pbkdf2_hmac('sha256', password_to_check_in_database.encode(), salt, 100000)

                        if hashed_password == hashed_request_pass:
                            print(f"username to check in database for chats is: {username_to_check_in_database}")
                            chats = database.get_chats(username_to_check_in_database)
                            groups = database.get_groups(username_to_check_in_database)

                            for chat_id, chat_name in chats:
                                users = database.get_chat_participants(chat_id)
                                sender, recipient = users
                                messages = database.get_messages(chat_id, sender, recipient)
                                # send the message history
                                protocol.send(client_socket, f"MESSAGE_HISTORY;{chat_name};{messages}")

                            for chat_id in groups:
                                chat_id = chat_id[0]
                                user1 = chat_id.split("_", 4)[0]
                                user2 = chat_id.split("_", 4)[1]
                                user3 = chat_id.split("_", 4)[2]
                                user4 = chat_id.split("_", 4)[3]
                                user5 = chat_id.split("_", 4)[4]
                                group_name = f"Group Chat {user1}, {user2}"
                                if user3 != "None":
                                    group_name += ", " + user3
                                if user4 != "None":
                                    group_name += ", " + user4
                                if user5 != "None":
                                    group_name += ", " + user5
                                messages = []
                                protocol.send(client_socket, f"MESSAGE_HISTORY;{group_name};{messages}")

                            protocol.send(client_socket, f"USER_IN_DATABASE")
                            break
                        else:
                            protocol.send(client_socket, f"PASSWORD_INCORRECT")
                            break
                    else:
                        protocol.send(client_socket, f"USER_DOES_NOT_EXIST")
                        break
                elif identifier == "SIGN_UP":
                    validation_message = validate_password(username_to_check_in_database, password_to_check_in_database)
                    if validation_message:
                        protocol.send(client_socket, f"PASSWORD_INVALID;{validation_message}")
                        break
                    else:
                        salt = os.urandom(2048)
                        hashed_pass = hashlib.pbkdf2_hmac('sha256', password_to_check_in_database.encode(), salt, 100000)
                        print("password encrypted")
                        if database.register_user(username_to_check_in_database, client_ip, hashed_pass, salt):
                            protocol.send(client_socket, f"SIGNED_UP")
                            break
                        else:
                            protocol.send(client_socket, f"ALREADY_EXISTS")
                            break

            # message is to create a new chat
            elif msg.startswith('CHECK_NEW_CHAT;'):
                username_to_check_for_existence = msg.split(';', 1)[1]
                if database.user_exists(username_to_check_for_existence):
                    if database.chat_exists(username, username_to_check_for_existence):
                        protocol.send(client_socket, f"CHECK_NEW_CHAT;CHAT_ALREADY_EXISTS")
                    else:
                        # add the new chat to the database
                        database.add_chat(username, username_to_check_for_existence)
                        protocol.send(client_socket, f"CHECK_NEW_CHAT;USER_EXISTS_CLEAR_TO_ADD")

                else:
                    protocol.send(client_socket, f"CHECK_NEW_CHAT;USER_DOES_NOT_EXISTS")

            # message is to create a new chat
            elif msg.startswith('CHECK_NEW_CHAT_GROUP;'):
                username_to_check_for_existence = msg.split(';', 1)[1]
                if database.user_exists(username_to_check_for_existence):
                    protocol.send(client_socket, f"CHECK_NEW_CHAT_GROUP;USER_EXISTS_CLEAR_TO_ADD")
                else:
                    protocol.send(client_socket, f"CHECK_NEW_CHAT_GROUP;USER_DOES_NOT_EXISTS")

            # message is to save a file in the recipient end in the database
            elif msg.startswith("SAVED_FILE;"):
                sender_username = msg.split(";", 5)[1]
                recipient_username = msg.split(";", 5)[2]
                time_sent = msg.split(";", 5)[3]
                type_file = msg.split(";", 5)[4]
                new_path_sender = msg.split(";", 5)[5]
                database.get_file_path(recipient_username, sender_username, time_sent, type_file, new_path_sender)
            # message is for deleting a chat

            elif msg.startswith("DELETE_CHAT;"):
                user_to_delete = msg.split(";", 2)[1]
                current_user = msg.split(";", 2)[2]
                if current_user in clients:
                    # Get the socket of the recipient client
                    user_socket = clients[current_user]
                    protocol.send(user_socket, f"@;DELETE_CHAT;{user_to_delete}")
                database.delete_chat(current_user, user_to_delete)
            # private msg
            elif msg.startswith('@'):
                if ' ' in msg:
                    # Extract the recipient's username
                    recipient_username = msg.split(' ')[0][1:]
                    # Extract the actual message content
                    # +2 to remove the @ and the space
                    msg_content = msg[len(recipient_username)+2:]

                    send_private_message(msg_content, username, recipient_username, client_socket)

                else:
                    print(f"Invalid message format: {msg}")

            # broadcast message
            elif msg.startswith('$'):
                if ' ' in msg:
                    # Extract the recipient's username
                    recipient_username = msg.split(' ')[0][1:]
                    # Extract the actual message content
                    # +2 to remove the @ and the space
                    msg_content = msg[len(recipient_username) + 2:]

                    broadcast(msg_content, username, recipient_username, client_socket)

                else:
                    print(f"Invalid message format: {msg}")

        except (ConnectionResetError, BrokenPipeError):
            print("A client has disconnected.")

            for username, socket_to_find in clients.items():
                if socket_to_find == client_socket:
                    del clients[username]
                    del public_keys[username]
                    print(f"Removed {username} from clients.")
                    break
            client_socket.close()
            break
        except Exception as e:
            print(f"[ERROR] Exception: {str(e)}")
            import traceback
            traceback.print_exc()
            break


def send_private_message(msg_content, username, recipient_username, client_socket):
    global recipient_socket
    if msg_content.startswith('MESSAGE_CHECK;'):
        if recipient_username in clients and recipient_username in public_keys:
            protocol.send(client_socket, "USER_ONLINE")
            recipient_socket = clients[recipient_username]
        else:
            print(f"User {recipient_username} not found. in MESSAGE_CHECK")
            protocol.send(client_socket, "USER_OFFLINE")
            # Handle the case where the recipient is not found
    # message is a file chunk
    elif msg_content.startswith('FILE_CHUNK;'):
        print("Handling FILE_CHUNK message in handle_client")
        filename = msg_content.split(';', 3)[1]
        chunk_data = msg_content.split(";", 3)[2]
        chunk_hash = msg_content.split(";", 3)[3]
        print("sending chunk in server")
        # Send the chunk
        protocol.send(recipient_socket, f"@;FILE_CHUNK;{recipient_username};{filename};{chunk_data};{chunk_hash}")

    # message is the end of file indicator
    elif msg_content.startswith('END_OF_FILE;'):
        filename_receiver = msg_content.split(';', 2)[1]
        filename_sender = msg_content.split(';', 2)[2]
        print("sending END_OF_FILE indicator in handle_client")
        # Send the end of file indicator
        protocol.send(recipient_socket, f"@;END_OF_FILE;{username};{recipient_username};{filename_receiver}")
        database.add_message(username, recipient_username, filename_receiver, filename_sender, "FILE")

    # message is a photo chunk
    elif msg_content.startswith('PHOTO_CHUNK;'):  # file msg
        print("Handling PHOTO_CHUNK message in handle_client")
        filename = msg_content.split(';', 3)[1]
        chunk_data = msg_content.split(";", 3)[2]
        chunk_hash = msg_content.split(";", 3)[3]
        # Send the chunk
        protocol.send(recipient_socket, f"@;PHOTO_CHUNK;{recipient_username};{filename};{chunk_data};{chunk_hash}")

    # message is the end of photo indicator
    elif msg_content.startswith('END_OF_PHOTO;'):
        filename_receiver = msg_content.split(';', 2)[1]
        filename_sender = msg_content.split(';', 2)[2]
        # Send the end of photo indicator
        print("sending end of photo in server")
        protocol.send(recipient_socket, f"@;END_OF_PHOTO;{username};{recipient_username};{filename_receiver}")
        database.add_message(username, recipient_username, filename_receiver, filename_sender, "PHOTO")

    # message is a video chunk
    elif msg_content.startswith('VIDEO_CHUNK;'):  # file msg
        print("Handling VIDEO_CHUNK message in handle_client")
        filename = msg_content.split(';', 3)[1]
        chunk_data = msg_content.split(";", 3)[2]
        chunk_hash = msg_content.split(";", 3)[3]
        # Send the chunk
        protocol.send(recipient_socket, f"@;VIDEO_CHUNK;{recipient_username};{filename};{chunk_data};{chunk_hash}")

    # message is the end of video indicator
    elif msg_content.startswith('END_OF_VIDEO;'):
        filename_receiver = msg_content.split(';', 2)[1]
        filename_sender = msg_content.split(';', 2)[2]
        # Send the end of video indicator
        print("sending end of video in server")
        protocol.send(recipient_socket, f"@;END_OF_VIDEO;{username};{recipient_username};{filename_receiver}")
        database.add_message(username, recipient_username, filename_receiver, filename_sender, "VIDEO")

    # message is an audio chunk
    elif msg_content.startswith('AUDIO_CHUNK;'):  # file msg
        print("Handling AUDIO_CHUNK message in handle_client")
        filename = msg_content.split(';', 3)[1]
        chunk_data = msg_content.split(";", 3)[2]
        chunk_hash = msg_content.split(";", 3)[3]
        # Send the chunk
        protocol.send(recipient_socket, f"@;AUDIO_CHUNK;{recipient_username};{filename};{chunk_data};{chunk_hash}")

    # message is the end of audio indicator
    elif msg_content.startswith('END_OF_AUDIO;'):
        filename_receiver = msg_content.split(';', 2)[1]
        filename_sender = msg_content.split(';', 2)[2]
        # Send the end of audio indicator
        print("sending end of audio in server")
        protocol.send(recipient_socket, f"@;END_OF_AUDIO;{username};{recipient_username};{filename_receiver}")
        database.add_message(username, recipient_username, filename_receiver, filename_sender, "AUDIO")

    # message is link
    elif msg_content.startswith('LINK;'):
        link_receiver = msg_content.split(';', 2)[1]
        link_sender = msg_content.split(';', 2)[2]

        protocol.send(recipient_socket, f"@;LINK;{username};{recipient_username};{link_receiver}")
        database.add_message(username, recipient_username, link_receiver, link_sender, "LINK")

    # message is a normal text message
    elif msg_content.startswith('MESSAGE;'):
        # Split the message into command and message content
        message_content_receiver = msg_content.split(";", 2)[1]
        message_content_sender = msg_content.split(";", 2)[2]

        # Send the message
        protocol.send(recipient_socket, f"@;MESSAGE;{username};{recipient_username};{message_content_receiver}")
        database.add_message(username, recipient_username, message_content_receiver, message_content_sender, "MESSAGE")


def broadcast(msg_content, username, recipient_username, client_socket):
    global recipient_socket
    print("in broadcast")
    if msg_content.startswith('MESSAGE_CHECK;'):
        if recipient_username in clients and recipient_username in public_keys:
            protocol.send(client_socket, "USER_ONLINE")
            # recipient_socket = clients[recipient_username]
        else:
            print(f"User {recipient_username} not found. in MESSAGE_CHECK")
            protocol.send(client_socket, "USER_OFFLINE")
            # Handle the case where the recipient is not found

    # message is for deleting a chat
    elif msg_content.startswith("DELETE_GROUP;"):
        group_to_delete = msg_content.split(";", 1)[1]
        print(f"user to send to: {recipient_username}")
        print(f"group to delete: {group_to_delete}")
        if recipient_username in clients:
            # Get the socket of the recipient client
            recipient_socket = clients[recipient_username]
            protocol.send(recipient_socket, f"$;DELETE_GROUP;{group_to_delete}")
        database.delete_group(group_to_delete)

    # message is a file chunk
    elif msg_content.startswith('FILE_CHUNK;'):
        print("Handling FILE_CHUNK message in handle_client")
        filename = msg_content.split(';', 3)[1]
        chunk_data = msg_content.split(";", 3)[2]
        chunk_hash = msg_content.split(";", 3)[3]

        recipient_socket = clients[recipient_username]

        # Send the chunk
        protocol.send(recipient_socket, f"$;FILE_CHUNK;{recipient_username};{filename};{chunk_data};{chunk_hash}")

    # message is the end of file indicator
    elif msg_content.startswith('END_OF_FILE;'):
        filename_receiver = msg_content.split(';', 3)[1]
        filename_sender = msg_content.split(';', 3)[2]
        chat_name = msg_content.split(";", 3)[3]
        recipient_socket = clients[recipient_username]
        print("sending END_OF_FILE indicator in handle_client")
        # Send the end of file indicator
        protocol.send(recipient_socket, f"$;END_OF_FILE;{chat_name};{username};{recipient_username};{filename_receiver}")
        # database.add_message(username, recipient_username, filename_receiver, filename_sender, "FILE")

    # message is a photo chunk
    elif msg_content.startswith('PHOTO_CHUNK;'):  # file msg
        print("Handling PHOTO_CHUNK message in handle_client")
        filename = msg_content.split(";", 3)[1]
        chunk_data = msg_content.split(";", 3)[2]
        chunk_hash = msg_content.split(";", 3)[3]
        recipient_socket = clients[recipient_username]
        # Send the chunk
        protocol.send(recipient_socket, f"$;PHOTO_CHUNK;{recipient_username};{filename};{chunk_data};{chunk_hash}")

    # message is the end of photo indicator
    elif msg_content.startswith('END_OF_PHOTO;'):
        filename_receiver = msg_content.split(';', 3)[1]
        filename_sender = msg_content.split(';', 3)[2]
        chat_name = msg_content.split(";", 3)[3]
        recipient_socket = clients[recipient_username]
        # Send the end of photo indicator
        protocol.send(recipient_socket, f"$;END_OF_PHOTO;{chat_name};{username};{recipient_username};{filename_receiver}")
        # database.add_message(username, recipient_username, filename_receiver, filename_sender, "PHOTO")

    # message is a video chunk
    elif msg_content.startswith('VIDEO_CHUNK;'):  # file msg
        print("Handling VIDEO_CHUNK message in handle_client")
        filename = msg_content.split(';', 3)[1]
        chunk_data = msg_content.split(";", 3)[2]
        chunk_hash = msg_content.split(";", 3)[3]

        recipient_socket = clients[recipient_username]
        # Send the chunk
        protocol.send(recipient_socket, f"$;VIDEO_CHUNK;{recipient_username};{filename};{chunk_data};{chunk_hash}")

    # message is the end of video indicator
    elif msg_content.startswith('END_OF_VIDEO;'):
        filename_receiver = msg_content.split(';', 3)[1]
        filename_sender = msg_content.split(';', 3)[2]
        chat_name = msg_content.split(";", 3)[3]
        recipient_socket = clients[recipient_username]

        # Send the end of video indicator
        protocol.send(recipient_socket, f"$;END_OF_VIDEO;{chat_name};{username};{recipient_username};{filename_receiver}")
        # database.add_message(username, recipient_username, filename_receiver, filename_sender, "VIDEO")

    # message is an audio chunk
    elif msg_content.startswith('AUDIO_CHUNK;'):  # file msg
        print("Handling AUDIO_CHUNK message in handle_client")
        filename = msg_content.split(';', 3)[1]
        chunk_data = msg_content.split(";", 3)[2]
        chunk_hash = msg_content.split(";", 3)[3]

        recipient_socket = clients[recipient_username]

        # Send the chunk
        protocol.send(recipient_socket, f"$;AUDIO_CHUNK;{recipient_username};{filename};{chunk_data};{chunk_hash}")

    # message is the end of audio indicator
    elif msg_content.startswith('END_OF_AUDIO;'):
        filename_receiver = msg_content.split(';', 3)[1]
        filename_sender = msg_content.split(';', 3)[2]
        chat_name = msg_content.split(";", 3)[3]
        recipient_socket = clients[recipient_username]

        # Send the end of audio indicator
        protocol.send(recipient_socket, f"$;END_OF_AUDIO;{chat_name};{username};{recipient_username};{filename_receiver}")
        # database.add_message(username, recipient_username, filename_receiver, filename_sender, "AUDIO")

    # message is link
    elif msg_content.startswith('LINK;'):
        link_receiver = msg_content.split(';', 3)[1]
        link_sender = msg_content.split(';', 3)[2]
        chat_name = msg_content.split(";", 3)[3]
        recipient_socket = clients[recipient_username]

        protocol.send(recipient_socket, f"$;LINK;{chat_name};{username};{recipient_username};{link_receiver}")
        # database.add_message(username, recipient_username, link_receiver, link_sender, "LINK")

    # message is a normal text message
    elif msg_content.startswith('MESSAGE;'):
        # Split the message into command and message content
        message_content_receiver = msg_content.split(";", 3)[1]
        message_content_sender = msg_content.split(";", 3)[2]
        chat_name = msg_content.split(";", 3)[3]
        recipient_socket = clients[recipient_username]
        # Send the message
        protocol.send(recipient_socket, f"$;MESSAGE;{chat_name};{username};{recipient_username};{message_content_receiver}")


# this function is to run the server and check for connections and to start the thread for handling the clients
def main():
    # start the server connection
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    # listen for connections
    server_socket.listen()
    print(f"[SERVER STARTED] listening on {HOST}:{PORT}")
    # star the thread for the handle client
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
    except KeyboardInterrupt:
        print("[SERVER SHUTDOWN] Closing all client connections...")
        for client_socket in clients.values():
            client_socket.close()
        server_socket.close()
        print("[SERVER SHUTDOWN] Server shut down successfully.")


if __name__ == "__main__":
    main()
