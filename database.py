import sqlite3
import time


# This function creates a new database if it doesn't exist yet.
def create_database():
    # Connect to the SQLite database
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    # Create a table for clients if it doesn't exist.
    c.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                username TEXT PRIMARY KEY,
                ip_address TEXT,
                password TEXT,
                salt TEXT
            )
        ''')

    # Create a table for chats if it doesn't exist.
    c.execute('''
            CREATE TABLE IF NOT EXISTS chats (
                chat_id TEXT PRIMARY KEY,
                user1 TEXT,
                user2 TEXT,
                FOREIGN KEY(user1) REFERENCES clients(username),
                FOREIGN KEY(user2) REFERENCES clients(username)
            )
        ''')

    # Create a table for messages if it doesn't exist.
    c.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT,
                sender TEXT,
                receiver TEXT,
                message_receiver TEXT,
                message_sender TEXT,
                time_sent TEXT,
                message_type TEXT,
                filepath_sender TEXT,
                FOREIGN KEY(chat_id) REFERENCES chats(chat_id),
                FOREIGN KEY(sender) REFERENCES clients(username)
            )
        ''')

    # Create a table for groups if it doesn't exist.
    c.execute('''
                CREATE TABLE IF NOT EXISTS groups (
                    chat_id TEXT PRIMARY KEY,
                    user1 TEXT,
                    user2 TEXT,
                    user3 TEXT,
                    user4 TEXT,
                    user5 TEXT,
                    FOREIGN KEY(user1) REFERENCES clients(username),
                    FOREIGN KEY(user2) REFERENCES clients(username),
                    FOREIGN KEY(user3) REFERENCES clients(username),
                    FOREIGN KEY(user4) REFERENCES clients(username),
                    FOREIGN KEY(user5) REFERENCES clients(username)
                )
            ''')
    # Commit the changes and close the connection to the database
    conn.commit()
    conn.close()


# This function registers a new user to the database.
def register_user(username, ip_address, password, salt):
    # Check if the user already exists
    if not user_exists(username):
        # Connect to the SQLite database
        conn = sqlite3.connect('clients.db')
        c = conn.cursor()

        # Insert the new user into the clients table
        c.execute('INSERT INTO clients VALUES (?, ?, ?, ?)', (username, ip_address, password, salt))

        # Commit the changes and close the connection to the database
        conn.commit()
        conn.close()
        return True
    return False


# This function checks if a user exists in the database.
def user_exists(username):
    # Connect to the SQLite database
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    # Query the clients table for the user
    c.execute('SELECT * FROM clients WHERE username = ?', (username,))
    user = c.fetchone()

    # Close the connection to the database
    conn.close()

    # Return True if the user exists, False otherwise
    return user is not None


# This function checks if a password is correct for a given username.
def check_password(username, password):
    # Connect to the SQLite database
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    # Query the clients table for the user's password
    c.execute("SELECT password FROM clients WHERE username=?", (username,))
    stored_password = c.fetchone()

    # Close the connection to the database
    conn.close()

    # Return True if the provided password matches the stored password, False otherwise
    return stored_password[0] == password


# This function prints all users in the database.
def print_all_users():
    # Connect to the SQLite database
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    # Select all users from the 'clients' table
    c.execute('SELECT * FROM clients')
    users = c.fetchall()

    # Close the connection to the database
    conn.close()

    # Print all users
    for user in users:
        print(f"username: {user[0]}, ip_address: {user[1]}, password: {user[2]}")


# This function deletes all users from the database.
def clean_database():
    # Connect to the SQLite database
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    # Delete all records from the 'clients' table
    c.execute("DELETE FROM clients")

    # Commit the changes and close the connection to the database
    conn.commit()
    conn.close()


# This function adds a new chat between two users to the database.
def add_chat(user1, user2):
    # Connect to the SQLite database
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    # Generate a chat ID from the usernames of the two users
    chat_id = user1 + "_" + user2

    # Insert the new chat into the chats table
    c.execute('INSERT INTO chats (chat_id, user1, user2) VALUES (?, ?, ?)', (chat_id, user1, user2))

    # Commit the changes and close the connection to the database
    conn.commit()
    conn.close()


# This function retrieves all chats of a user from the database.
def get_chats(username):
    # Connect to the SQLite database
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    # Select all chat IDs and usernames from the chats table where the user is a participant
    c.execute('SELECT chat_id, user2 FROM chats WHERE user1 = ?', (username,))
    chats = c.fetchall()

    # Close the connection to the database
    conn.close()

    # Return the list of chats
    return chats


# This function checks if a chat exists between two users in the database.
def chat_exists(user1, user2):
    # Connect to the SQLite database
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    # Check if a chat exists between user1 and user2
    c.execute('SELECT * FROM chats WHERE user1 = ? AND user2 = ?', (user1, user2))

    chat = c.fetchone()

    # Close the connection to the database
    conn.close()

    # Return True if the chat exists, False otherwise
    return chat is not None


# This function adds a new message to the database.
def add_message(sender, recipient, message_receiver, message_sender, message_type, filepath="Empty"):
    # Connect to the SQLite database
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    # Get the chat ID of the chat between the sender and the recipient
    c.execute('SELECT chat_id FROM chats WHERE user1 = ? AND user2 = ?', (sender, recipient))
    chat_id = c.fetchone()[0]

    # Get the current time
    time_sent = time.strftime('%Y-%m-%d %H:%M')

    # Insert the new message into the messages table
    c.execute('INSERT INTO messages (chat_id, sender, receiver, message_receiver, message_sender, time_sent, message_type, filepath_sender) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
              (chat_id, sender, recipient, message_receiver, message_sender, time_sent, message_type, filepath))

    # Commit the changes and close the connection to the database
    conn.commit()
    conn.close()


# This function retrieves all messages from a chat from the database.
def get_messages(chat_id, sender, receiver):
    # Connect to the SQLite database
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    # Get the chat ID of the other chat between the sender and the receiver
    other_chat_id = receiver + "_" + sender

    # Select all messages from the messages table where the chat ID is either chat_id or other_chat_id
    c.execute('SELECT * FROM messages WHERE chat_id = ? OR chat_id = ?', (chat_id, other_chat_id))
    messages = c.fetchall()

    # Close the connection to the database
    conn.close()

    # Return the list of messages
    return messages


# This function retrieves the participants of a chat from the database.
def get_chat_participants(chat_id):
    # Connect to the SQLite database
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    # Select the usernames of the participants of the chat from the chats table
    c.execute('SELECT user1, user2 FROM chats WHERE chat_id = ?', (chat_id,))
    users = c.fetchone()

    # Close the connection to the database
    conn.close()

    # Return the usernames of the participants
    return users


# This function retrieves the file path of a file from the database.
def get_file_path(sender, receiver, time_sent, message_type, new_path_sender):
    # Connect to the SQLite database
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    # Select the file path of the file from the messages table
    c.execute('SELECT filepath_sender FROM messages WHERE message_type = ? AND sender = ? AND receiver = ? AND time_sent = ?', (message_type, sender, receiver, time_sent))
    saved_file_sender = c.fetchone()

    print(f"sender is: {sender}")
    print(f"receiver is: {receiver}")
    print(f"message type is: {message_type}")
    print(f"time sent is: {time_sent}")
    print(f"new path is: {new_path_sender}")
    print(f"saved path is: {saved_file_sender}")
    # If the file path is "Empty", update it to new_path
    if saved_file_sender[0] == "Empty":
        c.execute('UPDATE messages SET filepath_sender = ? WHERE sender = ? AND receiver = ? AND time_sent = ? AND message_type = ?', (new_path_sender, sender, receiver, time_sent, message_type))
        conn.commit()
        saved_file_sender = new_path_sender

    # Close the connection to the database
    conn.close()

    # Return the file path
    return saved_file_sender


# this function gets two users and deletes their chat
def delete_chat(user1, user2):
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    chat_id1 = user1 + "_" + user2
    chat_id2 = user2 + "_" + user1

    # Create a SQL command to delete the chat
    sql_command1 = f"DELETE FROM chats WHERE chat_id = '{chat_id1}'"
    sql_command2 = f"DELETE FROM chats WHERE chat_id = '{chat_id2}'"

    # Execute the SQL command
    c.execute(sql_command1)
    c.execute(sql_command2)

    sql_command1 = f"DELETE FROM messages WHERE chat_id = '{chat_id1}'"
    sql_command2 = f"DELETE FROM messages WHERE chat_id = '{chat_id2}'"

    # Execute the SQL commands
    c.execute(sql_command1)
    c.execute(sql_command2)

    # Commit the changes
    conn.commit()
    conn.close()


# this function gets a username and returns the salt and password of the username
def get_salt_and_hashed_password(username):
    # Connect to the SQLite database
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    # Query the clients table for the salt and hashed password of the given username
    c.execute("SELECT salt, password FROM clients WHERE username=?", (username,))
    result = c.fetchone()

    # Close the connection to the database
    conn.close()

    if result is None:
        print(f"No user with username {username} found.")
        return None

    salt, hashed_password = result
    return salt, hashed_password


# This function adds a new chat between two users to the database.
def add_group(user1, user2, user3, user4, user5):
    # Connect to the SQLite database
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    # Generate a chat ID from the usernames of the two users
    chat_id = user1 + "_" + user2 + "_" + user3 + "_" + user4 + "_" + user5

    # Insert the new chat into the chats table
    c.execute('INSERT INTO groups (chat_id, user1, user2, user3, user4, user5) VALUES (?, ?, ?, ?, ?, ?)', (chat_id, user1, user2, user3, user4, user5))

    # Commit the changes and close the connection to the database
    conn.commit()
    conn.close()


# This function retrieves all chats of a user from the database.
def get_groups(username):
    # Connect to the SQLite database
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    # Select all chat IDs and usernames from the chats table where the user is a participant
    c.execute('SELECT chat_id FROM groups WHERE user1 = ? OR user2 = ? OR user3 = ? OR user4 = ? OR user5 = ?', (username, username, username, username, username))
    chats = c.fetchall()

    # Close the connection to the database
    conn.close()

    # Return the list of chats
    return chats


# this function gets two users and deletes their chat
def delete_group(group):
    conn = sqlite3.connect('clients.db')
    c = conn.cursor()

    users = group.replace("Group Chat ", "")
    list_of_users = users.split(', ')

    print(f"list of users is: {list_of_users}")
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
    chat_id = user1 + "_" + user2 + "_" + user3 + "_" + user4 + "_" + user5

    print(f"chat id to delete is: {chat_id}")
    # Create a SQL command to delete the chat
    sql_command1 = f"DELETE FROM groups WHERE chat_id = '{chat_id}'"
    # Execute the SQL command
    c.execute(sql_command1)

    # Commit the changes
    conn.commit()
    conn.close()
