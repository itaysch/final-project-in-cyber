import shutil
import threading
import tkinter as tk
from tkinter import messagebox, filedialog
from client import main, message_queue, database_check_queue, validate_user, validate_new_chat, database_check_new_chat_queue, offline_queue, delete_chat_queue, server_offline_queue, new_group_queue
import client
import base64
import os
import webbrowser
from tkinter import *
from PIL import ImageTk, Image
import cv2
import time
import pyaudio
import wave
import hashlib


Autor = "Itay Schlachet"


PORT = 9999  # port
CHUNK_SIZE = 4096
font = ('Arial', 16)
font_big = ('Arial', 20)


recording = False
frames = []
p = None
stream = None


username = ''
image_list = []

send_lock = threading.Lock()

# Define root before calling login
root = tk.Tk()
# To hide the main window
root.withdraw()


# this function gets nothing and logs in / sings up the user
def login():
    global user_info_label

    login_window = tk.Tk()
    login_window.title("Login")

    username_label = tk.Label(login_window, text="Username:", font=font)
    username_label.pack()
    username_entry = tk.Entry(login_window, font=font)
    username_entry.pack()

    password_label = tk.Label(login_window, text="Password:", font=font)
    password_label.pack()
    password_entry = tk.Entry(login_window, show="*", font=font)
    password_entry.pack()

    login_message_label = tk.Label(login_window, text="", font=font)
    login_message_label.pack()

    def submit_login():
        global username
        username = username_entry.get()
        password = password_entry.get()

        # Ensure all fields are filled
        if username and password:
            client.validate_user(username, password, "LOG_IN")
            command = server_offline_queue.get()
            if command == "SERVER_ONLINE":
                response_log_in = database_check_queue.get()

                if response_log_in == "USER_IN_DATABASE":
                    print("user is in database")
                    login_message_label.config(text=f"User {username} logged in.")

                    def connect_to_server():
                        # Call the main function with the username
                        main(username, "LOG_IN")
                        # Signal that login is done
                        login_done.set()

                    login_done = threading.Event()
                    threading.Thread(target=connect_to_server).start()
                    # Destroy the login window instead of destroying it
                    login_window.destroy()
                    # Show the main window
                    root.deiconify()
                    update_chat_list()

                elif response_log_in == "PASSWORD_INCORRECT":
                    login_message_label.config(text=f"Password {password}, is incorrect, please try again.")

                elif response_log_in == "USER_DOES_NOT_EXIST":
                    login_message_label.config(text=f"Username {username} does not exists. Please sign up.")

                user_info_label.config(text=f"Your Username: {username}")
            elif command == "SERVER_OFFLINE":
                login_message_label.config(text=f"Server is offline, try again later")

    def user_sign_up_window():
        global username
        sign_up_window = tk.Toplevel(login_window)
        sign_up_window.title("Sign Up")

        new_username_label = tk.Label(sign_up_window, text="New Username:", font=font)
        new_username_label.pack()
        new_username_entry = tk.Entry(sign_up_window, font=font)
        new_username_entry.pack()

        new_password_label = tk.Label(sign_up_window, text="New Password:", font=font)
        new_password_label.pack()
        new_password_entry = tk.Entry(sign_up_window, show="*", font=font)
        new_password_entry.pack()

        sign_up_message_label = tk.Label(sign_up_window, text="", font=font)
        sign_up_message_label.pack()

        def submit_sign_up():
            global username
            new_username = new_username_entry.get()
            new_password = new_password_entry.get()
            # Ensure all fields are filled
            if new_username and new_password:
                client.validate_user(new_username, new_password, "SIGN_UP")
                command = server_offline_queue.get()
                if command == "SERVER_ONLINE":
                    response_sign_up = database_check_queue.get()

                    if response_sign_up == "SIGNED_UP":
                        sign_up_message_label.config(text=f"User {new_username}, registered.")

                        def connect_to_server():
                            # Call the main function with the username
                            main(new_username, "SIGN_UP")
                            # Signal that login is done
                            login_done.set()

                        username = new_username
                        login_done = threading.Event()
                        threading.Thread(target=connect_to_server).start()
                        # Destroy the login window instead of destroying it
                        login_window.destroy()
                        # Show the main window
                        root.deiconify()

                        user_info_label.config(text=f"Your Username: {new_username}")
                    elif response_sign_up == "ALREADY_EXISTS":
                        sign_up_message_label.config(
                            text=f"Username {new_username} already exists. Please enter a different username.",
                            font=font)

                    elif response_sign_up.startswith("PASSWORD_INVALID"):
                        response = response_sign_up.split(";", 1)[1]
                        sign_up_message_label.config(text=f"{response}", font=font)

                elif command == "SERVER_OFFLINE":
                    sign_up_message_label.config(
                        text=f"Server is offline, try again later", font=font)

        sign_up_button_frame = tk.Frame(sign_up_window)
        sign_up_button_frame.pack(expand=True, fill=tk.BOTH)

        go_to_log_in_button = tk.Button(sign_up_button_frame, text="Log In", command=login, font=font, bg="light green")
        go_to_log_in_button.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        sign_up_button_submit = tk.Button(sign_up_button_frame, text="Submit", command=submit_sign_up, font=font, bg="light green")
        sign_up_button_submit.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

    login_button_frame = tk.Frame(login_window)
    login_button_frame.pack(expand=True, fill=tk.BOTH)

    submit_button = tk.Button(login_button_frame, text="Submit", command=submit_login, font=font, bg="light green")
    submit_button.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

    sign_up_button = tk.Button(login_button_frame, text="Sign Up", command=user_sign_up_window, font=font, bg="light green")
    sign_up_button.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)


# Call the login function before creating the main window
login()

root.title("Messenger App")
# Window size
root.geometry("1088x500")


# this function is to create a new chat
def create_new_chat():
    global chat_count

    # Create a new window
    new_chat_window = tk.Toplevel(root)
    new_chat_window.title("New Chat")

    # Create entry fields for chat name, IP address, and port
    chat_name_label = tk.Label(new_chat_window, text="Chat Name:", font=font)
    chat_name_label.pack()
    chat_name_entry = tk.Entry(new_chat_window, font=font)
    chat_name_entry.pack()
    chat_message_label = tk.Label(new_chat_window, text="", font=font)
    chat_message_label.pack()

    # Function to create chat with entered details
    def create_chat():
        chat_name = chat_name_entry.get()

        if chat_name:  # Ensure chat name is filled
            if chat_name != username:
                client.validate_new_chat(chat_name)
                response = database_check_new_chat_queue.get()

                if response == "USER_EXISTS_CLEAR_TO_ADD":
                    print("username exists in create_chat")
                    chat_message_label.config(text=f"Chat {chat_name} created.")
                    user = chat_name
                    client.add_new_chat_in_all(user, username)

                    chat_key = f"{chat_name}"
                    chat_list.insert(tk.END, chat_key)
                    chat_log = tk.Text(frame, state='disabled', font=font,
                                       yscrollcommand=chat_scrollbar.set)

                    chat_log.tag_config("link", foreground="blue", underline=True)
                    chat_log.tag_config("hyperlink", foreground="blue", underline=True)

                    # Bind the open_file function to the "link" tag
                    chat_log.tag_bind("link", "<Button-1>", open_file)
                    # Bind the handle_link_click function to the "hyperlink" tag
                    chat_log.tag_bind("hyperlink", "<Button-1>", handle_link_click)

                    # Add the chat log to the chat_logs dictionary
                    chat_logs[chat_key] = chat_log

                    chat_log.pack(expand=True, fill=tk.BOTH)  # Pack the chat log into the frame
                    chat_scrollbar.config(command=chat_log.yview)  # Link scrollbar to the new chat log
                    message_entry.config(state=tk.NORMAL)
                    send_button.config(state=tk.NORMAL)
                    attachment_button.config(state=tk.NORMAL)
                    voice_message_button.config(state=tk.NORMAL)
                    chat_label.config(text=chat_name)
                    # Close the window after creating the chat
                    new_chat_window.destroy()
                elif response == "CHAT_ALREADY_EXISTS":
                    chat_message_label.config(text=f"chat name {chat_name} already exists. Please try again.")

                elif response == "USER_DOES_NOT_EXISTS":
                    print("user that is being added does not exist")
                    chat_message_label.config(text=f"chat name {chat_name} does not exist. Please try again.")
            else:
                chat_message_label.config(text=f"can not create a chat with yourself")

    # Create button to finalize the chat creation
    new_chat_button_frame = tk.Frame(new_chat_window)
    new_chat_button_frame.pack(expand=True, fill=tk.BOTH)

    create_button = tk.Button(new_chat_button_frame, text="Create", command=create_chat, font=font, bg="light gray")
    create_button.pack(expand=True, fill=tk.BOTH)


def create_group_chat():
    group_chat_window = tk.Toplevel(root)
    group_chat_window.title("New Group Chat")

    username_label = tk.Label(group_chat_window, text="Username:", font=font)
    username_label.pack()
    username_entry = tk.Entry(group_chat_window, font=font)
    username_entry.pack()

    group_chat_message_label = tk.Label(group_chat_window, text="", font=font)
    group_chat_message_label.pack()

    usernames = []

    def add_user():
        username_to_add = username_entry.get()
        print(username)
        if username:
            if username_to_add == username:
                group_chat_message_label.config(text="You cannot add yourself to the group.")
            elif username_to_add in usernames:
                group_chat_message_label.config(text="This user is already added.")
            elif len(usernames) >= 5:
                group_chat_message_label.config(text="A group can have a maximum of 5 users.")
            else:
                client.validate_new_chat_group(username_to_add)
                response = database_check_new_chat_queue.get()
                if response == "USER_EXISTS_CLEAR_TO_ADD":
                    usernames.append(username_to_add)
                    group_chat_message_label.config(text=f"User {username_to_add} added. Add another user or submit.")
                    # Clear the text box
                    username_entry.delete(0, 'end')
                elif response == "USER_DOES_NOT_EXISTS":
                    group_chat_message_label.config(text=f"User {username_to_add} does not exist.")

    def submit_group_chat():
        if usernames:
            usernames.insert(0, username)

            client.add_new_group_in_all(usernames, username)

            group_chat_message_label.config(text=f"Group chat created with users {', '.join(usernames)}")

            group_members = ', '.join(usernames)
            chat_name = f"Group Chat {group_members}"

            chat_key = f"{chat_name}"
            chat_list.insert(tk.END, chat_key)
            chat_log = tk.Text(frame, state='disabled', font=font,
                               yscrollcommand=chat_scrollbar.set)

            chat_log.tag_config("link", foreground="blue", underline=True)
            chat_log.tag_config("hyperlink", foreground="blue", underline=True)

            # Bind the open_file function to the "link" tag
            chat_log.tag_bind("link", "<Button-1>", open_file)
            # Bind the handle_link_click function to the "hyperlink" tag
            chat_log.tag_bind("hyperlink", "<Button-1>", handle_link_click)

            # Add the chat log to the chat_logs dictionary
            chat_logs[chat_key] = chat_log

            chat_log.pack(expand=True, fill=tk.BOTH)  # Pack the chat log into the frame
            chat_scrollbar.config(command=chat_log.yview)  # Link scrollbar to the new chat log
            message_entry.config(state=tk.NORMAL)
            send_button.config(state=tk.NORMAL)
            attachment_button.config(state=tk.NORMAL)
            voice_message_button.config(state=tk.NORMAL)
            chat_label.config(text=chat_name)
            group_chat_window.destroy()
        else:
            group_chat_message_label.config(text="No users added to the group chat.")

    add_user_button = tk.Button(group_chat_window, text="Add New User", command=add_user, font=font, bg="light gray")
    add_user_button.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

    submit_button = tk.Button(group_chat_window, text="Submit", command=submit_group_chat, font=font, bg="light gray")
    submit_button.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)


def check_new_group_queue():
    while not new_group_queue.empty():
        new_group_name = new_group_queue.get()
        if ',' in new_group_name:
            print(f"New group created: {new_group_name}")

            group_members = new_group_name.replace("'", "").replace("[", "").replace("]", "")

            chat_name = f"Group Chat {group_members}"

            chat_key = f"{chat_name}"
            chat_list.insert(tk.END, chat_key)
            chat_log = tk.Text(frame, state='disabled', font=font,
                               yscrollcommand=chat_scrollbar.set)

            chat_log.tag_config("link", foreground="blue", underline=True)
            chat_log.tag_config("hyperlink", foreground="blue", underline=True)

            # Bind the open_file function to the "link" tag
            chat_log.tag_bind("link", "<Button-1>", open_file)
            # Bind the handle_link_click function to the "hyperlink" tag
            chat_log.tag_bind("hyperlink", "<Button-1>", handle_link_click)

            # Add the chat log to the chat_logs dictionary
            chat_logs[chat_key] = chat_log

            chat_log.pack(expand=True, fill=tk.BOTH)  # Pack the chat log into the frame
            chat_scrollbar.config(command=chat_log.yview)  # Link scrollbar to the new chat log
            message_entry.config(state=tk.NORMAL)
            send_button.config(state=tk.NORMAL)
            attachment_button.config(state=tk.NORMAL)
            voice_message_button.config(state=tk.NORMAL)
            chat_label.config(text=chat_name)    # Check the queue again after 100ms

        else:
            print(f"New chat created: {new_group_name}")

            chat_name = new_group_name

            chat_key = f"{chat_name}"
            chat_list.insert(tk.END, chat_key)
            chat_log = tk.Text(frame, state='disabled', font=font,
                               yscrollcommand=chat_scrollbar.set)

            chat_log.tag_config("link", foreground="blue", underline=True)
            chat_log.tag_config("hyperlink", foreground="blue", underline=True)

            # Bind the open_file function to the "link" tag
            chat_log.tag_bind("link", "<Button-1>", open_file)
            # Bind the handle_link_click function to the "hyperlink" tag
            chat_log.tag_bind("hyperlink", "<Button-1>", handle_link_click)

            # Add the chat log to the chat_logs dictionary
            chat_logs[chat_key] = chat_log

            chat_log.pack(expand=True, fill=tk.BOTH)  # Pack the chat log into the frame
            chat_scrollbar.config(command=chat_log.yview)  # Link scrollbar to the new chat log
            message_entry.config(state=tk.NORMAL)
            send_button.config(state=tk.NORMAL)
            attachment_button.config(state=tk.NORMAL)
            voice_message_button.config(state=tk.NORMAL)
            chat_label.config(text=chat_name)  # Check the queue again after 100ms
    root.after(100, check_new_group_queue)


# this function is to switch between chats
def switch_chat(event):
    global chat_scrollbar
    active_chat = chat_logs[chat_list.get(tk.ACTIVE)]
    for chat_log in chat_logs.values():
        chat_log.pack_forget()
    active_chat.pack(expand=True, fill=tk.BOTH)
    chat_label.config(text=chat_list.get(tk.ACTIVE), bg="light green", fg="black")
    # Link scrollbar to active chat
    chat_scrollbar.config(command=active_chat.yview)
    message_entry.config(state=tk.NORMAL)
    send_button.config(state=tk.NORMAL)
    attachment_button.config(state=tk.NORMAL)
    voice_message_button.config(state=tk.NORMAL)


# this function is to delete a chat in the recipient end
def handle_delete_chat():
    while not delete_chat_queue.empty():
        print("deleting user in handle_delete_chat")
        selected_chat = delete_chat_queue.get()
        print(f"chat name to delete is: {selected_chat}")
        # Find the index of the chat
        chat_index = chat_list.get(0, tk.END).index(selected_chat)
        # Remove chat from chat_list
        chat_list.delete(chat_index)
        # Remove chat log from frame
        chat_logs[selected_chat].pack_forget()
        # Destroy the chat log widget
        chat_logs[selected_chat].destroy()
        # Remove chat log from chat_logs dictionary
        del chat_logs[selected_chat]

        message_entry.config(state=tk.DISABLED)
        send_button.config(state=tk.DISABLED)
        attachment_button.config(state=tk.DISABLED)
        voice_message_button.config(state=tk.DISABLED)
        chat_label.config(text="")

        chat_list.update()
        frame.update()
        # Check for new delete chat messages every 100ms
    root.after(100, handle_delete_chat)


# this function is to delete a chat in the sending end
def delete_chat():
    if messagebox.askokcancel("Delete Chat", "Are you sure you want to delete?"):
        selected_chat = chat_list.get(tk.ACTIVE)
        print(f"username: {username}, selected_chat: {selected_chat}")
        if ',' in selected_chat:
            client.send_message(f"$;DELETE_GROUP;{username};{selected_chat}", selected_chat)
        else:
            client.send_message(f"@;DELETE_CHAT;{username};{selected_chat}", selected_chat)
        # Remove chat from chat_list
        chat_list.delete(tk.ACTIVE)
        # Remove chat log from frame
        chat_logs[selected_chat].pack_forget()
        # Destroy the chat log widget
        chat_logs[selected_chat].destroy()
        # Remove chat log from chat_logs dictionary
        del chat_logs[selected_chat]
        message_entry.config(state=tk.DISABLED)
        send_button.config(state=tk.DISABLED)
        attachment_button.config(state=tk.DISABLED)
        voice_message_button.config(state=tk.DISABLED)
        chat_label.config(text="")
        chat_list.update()


# this function is to read the file the client choose and send it to the client class to be sent to the recipient, and update the sender log
def send_file(attachment_window=None):
    # Open the file dialog and get the selected file path
    filename = filedialog.askopenfilename()
    # Get the username of the selected chat
    recipient_username = chat_list.get(tk.ACTIVE)

    user_status = ""
    msg_header = ""
    msg_header_end = ""
    if ',' in recipient_username:
        msg_header = "$;FILE_CHUNK"
        msg_header_end = "$;END_OF_FILE"
        client.send_message(f"$;MESSAGE_CHECK;{username}", recipient_username)
        user_status = offline_queue.get()
    else:
        msg_header = "@;FILE_CHUNK"
        msg_header_end = "@;END_OF_FILE"
        client.send_message(f"@;MESSAGE_CHECK;{username}", recipient_username)
        user_status = offline_queue.get()

    if user_status == "USER_ONLINE":
        if filename and recipient_username:
            with open(filename, 'rb') as file:
                while True:
                    print("reading")
                    chunk = file.read(CHUNK_SIZE)
                    if not chunk:
                        # If the chunk is empty, end the loop
                        break
                    # Compute the SHA256 hash of the chunk
                    hash_obj = hashlib.sha256()
                    hash_obj.update(chunk)
                    chunk_hash = hash_obj.hexdigest()
                    chunk_data = base64.b64encode(chunk).decode()
                    # Send the chunk
                    client.send_message(f"{msg_header};{filename};{chunk_data};{username};{chunk_hash}", recipient_username)

                print("after break")
            print(f"sending end of file indicator in send_file. filename is {filename}")
            # Send the end of file indicator
            client.send_message(f"{msg_header_end};{filename};{username}", recipient_username)

            current_time = time.strftime('%H:%M')
            chat_logs[chat_list.get(tk.ACTIVE)].config(state=tk.NORMAL)
            # Add the "FILE:" prefix and the "link" tag to the link in the sender's chat
            chat_logs[chat_list.get(tk.ACTIVE)].insert(tk.END, f"You: FILE: {filename}\n", "link")
            chat_logs[chat_list.get(tk.ACTIVE)].insert(tk.END, current_time + "\n\n")
            chat_logs[chat_list.get(tk.ACTIVE)].config(state=tk.DISABLED)
            chat_logs[chat_list.get(tk.ACTIVE)].yview(tk.END)
            if attachment_window is not None:
                # Close the attachment window
                attachment_window.destroy()
        else:
            messagebox.showerror("Error", "No chat selected.")

    elif user_status == "USER_OFFLINE":
        messagebox.showinfo("Error", f"The user {recipient_username} is not online.")


# this function is to read the photo the client choose and send it to the client class to be sent to the recipient, and update the sender log
def send_photo(attachment_window, filename_taken, image_window):
    filename = filename_taken
    if filename_taken is None:
        # Only allow image file types
        filename = filedialog.askopenfilename(
            filetypes=[('Image Files', '*.png *.jpg *.jpeg *.gif')])
    # Get the username of the selected chat
    recipient_username = chat_list.get(tk.ACTIVE)

    user_status = ""
    msg_header = ""
    msg_header_end = ""
    if ',' in recipient_username:
        msg_header = "$;PHOTO_CHUNK"
        msg_header_end = "$;END_OF_PHOTO"
        client.send_message(f"$;MESSAGE_CHECK;{username}", recipient_username)
        user_status = offline_queue.get()
    else:
        msg_header = "@;PHOTO_CHUNK"
        msg_header_end = "@;END_OF_PHOTO"
        client.send_message(f"@;MESSAGE_CHECK;{username}", recipient_username)
        user_status = offline_queue.get()

    if user_status == "USER_ONLINE":
        if filename and recipient_username:
            with open(filename, 'rb') as file:
                while True:
                    # Read the file in chunks
                    chunk = file.read(CHUNK_SIZE)
                    if not chunk:
                        # If the chunk is empty, end the loop
                        break
                    # Compute the SHA256 hash of the chunk
                    hash_obj = hashlib.sha256()
                    hash_obj.update(chunk)
                    chunk_hash = hash_obj.hexdigest()

                    chunk_data = base64.b64encode(chunk).decode()
                    # Send the chunk
                    client.send_message(f"{msg_header};{filename};{chunk_data};{username};{chunk_hash}", recipient_username)

            print(f"sending end of photo indicator in send_photo. filename is {filename}")
            # Send the end of file indicator
            client.send_message(f"{msg_header_end};{filename};{username}", recipient_username)

            current_time = time.strftime('%H:%M')
            chat_logs[chat_list.get(tk.ACTIVE)].config(state=tk.NORMAL)
            # Add the "FILE:" prefix and the "link" tag to the link in the sender's chat
            chat_logs[chat_list.get(tk.ACTIVE)].insert(tk.END, f"You: PHOTO: {filename}\n", "link")

            image = Image.open(filename)
            image = resize_image(image)
            photo = ImageTk.PhotoImage(image)
            canvas = tk.Canvas(chat_logs[chat_list.get(tk.ACTIVE)], width=image.width, height=image.height)
            canvas.pack()
            # Create an image item on the canvas
            canvas.create_image(0, 0, image=photo, anchor='nw')
            canvas.image = photo
            chat_logs[chat_list.get(tk.ACTIVE)].window_create(tk.END, window=canvas)

            chat_logs[chat_list.get(tk.ACTIVE)].insert(tk.END, "" + "\n")
            chat_logs[chat_list.get(tk.ACTIVE)].insert(tk.END, current_time + "\n\n")

            chat_logs[chat_list.get(tk.ACTIVE)].config(state=tk.DISABLED)
            chat_logs[chat_list.get(tk.ACTIVE)].yview(tk.END)

            if attachment_window is not None and image_window is not None:
                # Close the attachment window
                attachment_window.destroy()
                image_window.destroy()

        else:
            messagebox.showerror("Error", "No chat selected.")

    elif user_status == "USER_OFFLINE":
        messagebox.showinfo("Error", f"The user {recipient_username} is not online.")


# this function is to read the video the client choose and send it to the client class to be sent to the recipient, and update the sender log
def send_video(attachment_window, filename_taken, video_window):
    filename = filename_taken
    if filename_taken is None:
        # Only allow video file types
        filename = filedialog.askopenfilename(filetypes=[('Video Files', '*.mp4 *.avi *.mov *.flv *.mkv')])
    # Get the username of the selected chat
    recipient_username = chat_list.get(tk.ACTIVE)

    user_status = ""
    msg_header = ""
    msg_header_end = ""
    if ',' in recipient_username:
        msg_header = "$;VIDEO_CHUNK"
        msg_header_end = "$;END_OF_VIDEO"
        client.send_message(f"$;MESSAGE_CHECK;{username}", recipient_username)
        user_status = offline_queue.get()
    else:
        msg_header = "@;VIDEO_CHUNK"
        msg_header_end = "@;END_OF_VIDEO"
        client.send_message(f"@;MESSAGE_CHECK;{username}", recipient_username)
        user_status = offline_queue.get()

    if user_status == "USER_ONLINE":
        if filename and recipient_username:
            with open(filename, 'rb') as file:
                while True:
                    # Read the file in chunks
                    chunk = file.read(CHUNK_SIZE)
                    if not chunk:
                        # If the chunk is empty, end the loop
                        break
                    # Compute the SHA256 hash of the chunk
                    hash_obj = hashlib.sha256()
                    hash_obj.update(chunk)
                    chunk_hash = hash_obj.hexdigest()

                    chunk_data = base64.b64encode(chunk).decode()
                    # Send the chunk
                    client.send_message(f"{msg_header};{filename};{chunk_data};{username};{chunk_hash}", recipient_username)

            print(f"sending end of photo indicator in send_video. filename is {filename}")
            # Send the end of file indicator
            client.send_message(f"{msg_header_end};{filename};{username}", recipient_username)

            current_time = time.strftime('%H:%M')
            chat_logs[chat_list.get(tk.ACTIVE)].config(state=tk.NORMAL)
            # Add the "FILE:" prefix and the "link" tag to the link in the sender's chat
            chat_logs[chat_list.get(tk.ACTIVE)].insert(tk.END, f"You: VIDEO: {filename}\n", "link")

            play_button = tk.Button(chat_logs[chat_list.get(tk.ACTIVE)], text="Play", command=lambda: create_video_player(filename), font=font, fg="black", bg="lightblue")
            chat_logs[chat_list.get(tk.ACTIVE)].window_create(tk.END, window=play_button)

            chat_logs[chat_list.get(tk.ACTIVE)].insert(tk.END, current_time + "\n\n")
            chat_logs[chat_list.get(tk.ACTIVE)].config(state=tk.DISABLED)
            chat_logs[chat_list.get(tk.ACTIVE)].yview(tk.END)

            if attachment_window is not None and video_window is not None:
                # Close the attachment window
                attachment_window.destroy()
                video_window.destroy()

        else:
            messagebox.showerror("Error", "No chat selected.")

    elif user_status == "USER_OFFLINE":
        messagebox.showinfo("Error", f"The user {recipient_username} is not online.")


def create_video_player(filename):
    # Create a new Tkinter window
    video_play_window = tk.Toplevel(root)

    # filename = filedialog.askopenfilename(filetypes=[('Video Files', '*.mp4 *.avi *.mov *.flv *.mkv')])
    # Open the video file
    cap = cv2.VideoCapture(filename)

    # Get the video's width and height
    video_width = cap.get(cv2.CAP_PROP_FRAME_WIDTH)
    video_height = cap.get(cv2.CAP_PROP_FRAME_HEIGHT)

    # Set the window's size to the video's size
    video_play_window.geometry(f'{int(video_width)}x{int(video_height) + 88}')

    # Create a canvas for the video
    canvas = tk.Canvas(video_play_window, width=video_width, height=video_height)
    canvas.pack()

    # Create a stop flag
    stop_flag = False

    # Function to stream the video
    def stream_video():
        global stop_flag
        global photo_objects
        print(stop_flag)
        if not stop_flag:
            # Read a frame from the video
            ret, frame = cap.read()

            if ret:
                # Convert the frame to PIL Image format
                image = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))

                # Convert the PIL Image to ImageTk format
                photo = ImageTk.PhotoImage(image)

                # Keep a reference to the photo object to prevent it from being garbage collected
                canvas.photo = photo

                # Add the image to the canvas
                canvas.create_image(0, 0, image=photo, anchor=tk.NW)

                # Call this function again after 20 milliseconds to get the next frame
                video_play_window.after(20, stream_video)
            else:
                # If there are no more frames, stop the video
                cap.release()

    # Function to stop the video
    def stop_video():
        global stop_flag
        stop_flag = True
        play_stop_button.config(text="Play", command=stream_video1, bg="light green")

    def stream_video1():
        global stop_flag
        stop_flag = False
        stream_video()
        play_stop_button.config(text="Stop", command=stop_video, bg="salmon")

    def close_video_window():
        stop_video()
        cap.release()
        video_play_window.destroy()

    # Create a button that stops the video when clicked
    play_stop_button = tk.Button(
        video_play_window,  # the window the button will be added to
        text="Play",  # the text on the button
        font=("Arial", 24),  # the font and size of the text
        fg="black",  # the color of the text (fg stands for foreground)
        bg="light green",  # the color of the button (bg stands for background)
        width=10,  # the width of the button (in characters)
        height=2,  # the height of the button (in lines of text)
        command=stream_video1  # the function to call when the button is clicked
    )
    play_stop_button.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

    # Create a button that stops the video when clicked
    close_window_video = tk.Button(
        video_play_window,  # the window the button will be added to
        text="Close",  # the text on the button
        font=("Arial", 24),  # the font and size of the text
        fg="black",  # the color of the text (fg stands for foreground)
        bg="gray",  # the color of the button (bg stands for background)
        width=10,  # the width of the button (in characters)
        height=2,  # the height of the button (in lines of text)
        command=close_video_window  # the function to call when the button is clicked
    )
    close_window_video.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
    video_play_window.protocol("WM_DELETE_WINDOW", close_video_window)


# this function is to take an image with the default camera and send it to the send photo function
def take_image(attachment_window, image_window):
    cap = cv2.VideoCapture(0)
    ret, frame_image = cap.read()

    current_time_seconds = int(time.time())

    filename = f"photo_taken_{current_time_seconds}.jpg"
    cv2.imwrite(filename, frame_image)
    cap.release()
    cv2.destroyAllWindows()
    if filename:
        send_photo(attachment_window, filename, image_window)


# this function is to record a video and send it to the send video function
def record_video(attachment_window, video_window):
    cap = cv2.VideoCapture(0)
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')

    current_time_seconds = int(time.time())

    out = cv2.VideoWriter(f'output_{current_time_seconds}.avi', fourcc, 20.0, (640, 480))

    start_time = time.time()

    print("recording")

    while cap.isOpened():
        ret, frame_video = cap.read()
        if ret:
            out.write(frame_video)
            if time.time() - start_time > 10:
                break
        else:
            break

    cap.release()
    out.release()
    cv2.destroyAllWindows()
    filename = f"output_{current_time_seconds}.avi"
    if filename:
        send_video(attachment_window, filename, video_window)


# this function is for the window of sending a photo
def open_image_window(attachment_window=None):
    filename_taken = None

    image_window = tk.Toplevel(root)
    image_window.title("Open Image")

    select_image_button = Button(image_window, text="Select Image from Files",
                                 command=lambda: send_photo(attachment_window, filename_taken, image_window), font=font_big, bg="light gray")
    select_image_button.pack(fill=tk.X)
    take_image_button = Button(image_window, text="Take Image",
                               command=lambda: take_image(attachment_window, image_window), font=font_big, bg="light gray")
    take_image_button.pack(fill=tk.X)


# this function is for the window of sending a video
def open_video_window(attachment_window=None):
    filename_taken = None

    video_window = Toplevel(root)
    video_window.title("Open Video")

    select_video_button = Button(video_window, text="Select Video from Files",
                                 command=lambda: send_video(attachment_window, filename_taken, video_window), font=font_big, bg="light gray")
    select_video_button.pack(fill=tk.X)
    record_video_button = Button(video_window, text="Record Video",
                                 command=lambda: record_video(attachment_window, video_window), font=font_big, bg="light gray")
    record_video_button.pack(fill=tk.X)


def resize_image(image, max_width=300, max_height=240):
    image_width = image.width
    image_height = image.height

    # If the image is horizontal
    if image_width > image_height:
        if image_width > max_width:
            # Calculate the ratio of the new width to the original width
            ratio = max_width / float(image_width)
            # Calculate the new height based on the ratio
            image_height = int(image_height * ratio)
            # Set the width to the maximum width
            image_width = max_width
    else:  # If the image is vertical
        if image_height > max_height:
            # Calculate the ratio of the new height to the original height
            ratio = max_height / float(image_height)
            # Calculate the new width based on the ratio
            image_width = int(image_width * ratio)
            # Set the height to the maximum height
            image_height = max_height

    # Resize the image
    image = image.resize((image_width, image_height))

    return image


# this function is for the window of the attachment sending and choosing
def open_attachment_window():
    # display_attachment()
    attachment_window = tk.Toplevel(root)
    attachment_window.title("Send Attachment")
    # attachment_window.geometry("800x600")

    send_file_button = tk.Button(attachment_window, text="Send File", command=lambda: send_file(attachment_window),
                                 font=font_big, bg="light gray")
    send_file_button.pack(fill=tk.X)

    # Associate send_photo function with the "Send Image" button
    send_image_button = tk.Button(attachment_window, text="Send Image",
                                  command=lambda: open_image_window(attachment_window), font=font_big, bg="light gray")
    send_image_button.pack(fill=tk.X)

    send_video_button = tk.Button(attachment_window, text="Send Video",
                                  command=lambda: open_video_window(attachment_window), font=font_big, bg="light gray")
    send_video_button.pack(fill=tk.X)

    send_link_button = tk.Button(attachment_window, text="Send Link",
                                 command=lambda: open_link_window(attachment_window), font=font_big, bg="light gray")
    send_link_button.pack(fill=tk.X)


# this function get what the user wrote in the message box and sends the text message to the client class to send to the recipient, and update the sender log
def send_message_in_tkinter(event=None):
    msg = message_entry.get()
    print("msg in send_message_in_tkinter " + msg)
    if msg != "":
        # Get the username of the selected chat
        recipient_username = chat_list.get(tk.ACTIVE)

        user_status = ""
        msg_header = ""
        if ',' in recipient_username:
            msg_header = "$;MESSAGE"
            client.send_message(f"$;MESSAGE_CHECK;{username}", recipient_username)
            user_status = offline_queue.get()
        else:
            msg_header = "@;MESSAGE"
            client.send_message(f"@;MESSAGE_CHECK;{username}", recipient_username)
            user_status = offline_queue.get()

        if user_status == "USER_ONLINE":
            print(f"username in tkinter = {username}")
            client.send_message(f"{msg_header};{msg};{username}", recipient_username)

            chat_logs[chat_list.get(tk.ACTIVE)].config(state=tk.NORMAL)
            current_time = time.strftime('%H:%M')

            chat_logs[chat_list.get(tk.ACTIVE)].insert(tk.END, "You: " + msg + "\n")
            chat_logs[chat_list.get(tk.ACTIVE)].insert(tk.END, current_time + "\n\n")
            chat_logs[chat_list.get(tk.ACTIVE)].config(state=tk.DISABLED)
            chat_logs[chat_list.get(tk.ACTIVE)].yview(tk.END)
            message_entry.delete(0, tk.END)

        elif user_status == "USER_OFFLINE":
            messagebox.showinfo("Error", f"The user {recipient_username} is not online.")


# this function is to save a file locally in the decided location, and send it to the client class to be updated eventually in the database, and update the sender log
def save_file(event, full_path, base_filename, sender_username, type_file, current_time, receiver, log, original_path,
              time_sent):
    # Open a save file dialog
    new_path = filedialog.asksaveasfilename(initialfile=base_filename, defaultextension=".*")
    print("in save_file")
    if new_path:
        print(f"fullpath is: {full_path}")
        temp_dir = r"C:\Users\Public"
        new_full_path = os.path.join(temp_dir, base_filename)
        # Move the file to the chosen location
        shutil.move(new_full_path, new_path)
        if log == "LOGGING":
            print(f"sending the saved_file to send_message base = {base_filename}")
            if ',' not in sender_username and ',' not in receiver:
                client.send_message(f"@;SAVED_FILE;{sender_username};{receiver};{time_sent};{type_file};{new_path}", username)

        chat_logs[chat_list.get(tk.ACTIVE)].config(state=tk.NORMAL)
        print(f"time sent is: {time_sent}")
        print(f"receiver is: {receiver}")
        print(f"type file is: {type_file}")
        print(f"sender is: {sender_username}")
        print(f"base file name is: {os.path.basename(original_path)}")
        # Find the index of the "choose where to save" line
        line_index = None
        if ',' in receiver:
            for i, line in enumerate(chat_logs[chat_list.get(tk.ACTIVE)].get('1.0', tk.END).split('\n')):
                print(f"line is: {line}")
                if f"{sender_username}: {type_file}: choose where to save the file: {os.path.basename(original_path)}" in line:
                    line_index = i
                    break
        else:
            for i, line in enumerate(chat_logs[chat_list.get(tk.ACTIVE)].get('1.0', tk.END).split('\n')):
                print(f"line is: {line}")
                if f"{receiver}: {type_file}: choose where to save the file: {os.path.basename(original_path)}" in line:
                    line_index = i
                    break
        print(f"line index is: {line_index}")
        if line_index is not None:
            # Delete the "choose where to save" line and the two lines after it
            chat_logs[chat_list.get(tk.ACTIVE)].delete(f"{line_index + 1}.0", f"{line_index + 4}.0")
            print("deleted lines and inserting new")

        if type_file == "PHOTO":
            if ',' in receiver:
                chat_logs[chat_list.get(tk.ACTIVE)].insert(f"{line_index + 1}.0", f"{sender_username}: PHOTO: {new_path}\n", "link")
            else:
                chat_logs[chat_list.get(tk.ACTIVE)].insert(f"{line_index + 1}.0", f"{receiver}: PHOTO: {new_path}\n", "link")

            image = Image.open(new_path)
            image = resize_image(image)
            photo = ImageTk.PhotoImage(image)
            canvas = tk.Canvas(chat_logs[chat_list.get(tk.ACTIVE)], width=image.width, height=image.height)
            canvas.pack()
            # Create an image item on the canvas
            canvas.create_image(0, 0, image=photo, anchor='nw')
            canvas.image = photo
            chat_logs[chat_list.get(tk.ACTIVE)].window_create(f"{line_index + 2}.0", window=canvas)

            chat_logs[chat_list.get(tk.ACTIVE)].insert(f"{line_index + 3}.0", "" + "\n")
            chat_logs[chat_list.get(tk.ACTIVE)].insert(f"{line_index + 3}.0", current_time + "\n")

        elif type_file == "FILE":
            if ',' in receiver:
                chat_logs[chat_list.get(tk.ACTIVE)].insert(f"{line_index + 1}.0", f"{sender_username}: FILE: {new_path}\n",
                                                           "link")
            else:
                chat_logs[chat_list.get(tk.ACTIVE)].insert(f"{line_index + 1}.0", f"{receiver}: FILE: {new_path}\n",
                                                           "link")
            chat_logs[chat_list.get(tk.ACTIVE)].insert(f"{line_index + 2}.0", current_time + "\n\n")

        elif type_file == "VIDEO":
            if ',' in receiver:
                chat_logs[chat_list.get(tk.ACTIVE)].insert(f"{line_index + 1}.0", f"{sender_username}: VIDEO: {new_path}\n",
                                                           "link")
            else:
                chat_logs[chat_list.get(tk.ACTIVE)].insert(f"{line_index + 1}.0", f"{receiver}: VIDEO: {new_path}\n",
                                                           "link")
            play_button = tk.Button(chat_logs[chat_list.get(tk.ACTIVE)], text="Play", command=lambda: create_video_player(new_path), font=font, fg="black", bg="lightblue")
            chat_logs[chat_list.get(tk.ACTIVE)].window_create(f"{line_index + 2}.0", window=play_button)
            chat_logs[chat_list.get(tk.ACTIVE)].insert(f"{line_index + 2}.1", current_time + "\n\n")

        elif type_file == "AUDIO":
            if ',' in receiver:
                chat_logs[chat_list.get(tk.ACTIVE)].insert(f"{line_index + 1}.0", f"{sender_username}: AUDIO: {new_path}\n",
                                                           "link")
            else:
                chat_logs[chat_list.get(tk.ACTIVE)].insert(f"{line_index + 1}.0", f"{receiver}: AUDIO: {new_path}\n",
                                                           "link")
            chat_logs[chat_list.get(tk.ACTIVE)].insert(f"{line_index + 2}.0", current_time + "\n\n")

        chat_logs[chat_list.get(tk.ACTIVE)].config(state=tk.DISABLED)
        chat_logs[chat_list.get(tk.ACTIVE)].yview(tk.END)


# this function is to open a file when clicked on in the chat log
def open_file(event):
    # Get the index of the clicked link
    index = chat_logs[chat_list.get(tk.ACTIVE)].index(tk.CURRENT)
    # Get the line containing the clicked link
    line = chat_logs[chat_list.get(tk.ACTIVE)].get(f"{index} linestart", f"{index} lineend")
    if "FILE:" in line:
        print("FILE is in line")
        # Split the line into two parts at "FILE:" and take the second part as the filename
        filename = line.split("FILE:", 1)[1].strip()
        try:
            # Open the file
            os.startfile(filename)
        except Exception as e:
            messagebox.showerror("Error", "Could not open file: " + str(e))

    elif "PHOTO:" in line:
        print("PHOTO is in line")
        # Split the line into two parts at "FILE:" and take the second part as the filename
        filename = line.split("PHOTO:", 1)[1].strip()
        try:
            # Open the file
            os.startfile(filename)
        except Exception as e:
            messagebox.showerror("Error", "Could not open file: " + str(e))

    elif "VIDEO:" in line:
        print("VIDEO is in line")
        # Split the line into two parts at "FILE:" and take the second part as the filename
        filename = line.split("VIDEO:", 1)[1].strip()
        try:
            # Open the file
            os.startfile(filename)
        except Exception as e:
            messagebox.showerror("Error", "Could not open file: " + str(e))

    elif "AUDIO:" in line:
        print("AUDIO is in line")
        # Split the line into two parts at "FILE:" and take the second part as the filename
        filename = line.split("AUDIO:", 1)[1].strip()
        try:
            # Open the file
            os.startfile(filename)
        except Exception as e:
            messagebox.showerror("Error", "Could not open file: " + str(e))

    else:
        print("FILE is not in line")


# this function is for the link sending window and for sending the link to the client class to be sent to the recipient, and update the sender log
def open_link_window(attachment_window=None):
    link_window = tk.Toplevel(root)
    link_window.title("Send Link")

    link_label = tk.Label(link_window, text="Paste Link:", font=font_big)
    link_label.pack(expand=True, fill=tk.BOTH)

    link_entry = tk.Entry(link_window, font=font)
    link_entry.pack(expand=True, fill=tk.BOTH)

    def send_link():
        link = link_entry.get()
        if link:
            recipient_username = chat_list.get(tk.ACTIVE)

            user_status = ""
            msg_header = ""
            if ',' in recipient_username:
                msg_header = "$;LINK"
                client.send_message(f"$;MESSAGE_CHECK;{username}", recipient_username)
                user_status = offline_queue.get()
            else:
                msg_header = "@;LINK"
                client.send_message(f"@;MESSAGE_CHECK;{username}", recipient_username)
                user_status = offline_queue.get()

            if user_status == "USER_ONLINE":
                if link and recipient_username:
                    client.send_message(f"{msg_header};{link};{username}", recipient_username)
                    current_time = time.strftime('%H:%M')
                    chat_logs[chat_list.get(tk.ACTIVE)].config(state=tk.NORMAL)

                    # Display link in sender's chat log
                    chat_logs[chat_list.get(tk.ACTIVE)].insert(tk.END, f"You: LINK: {link}\n", "hyperlink")
                    chat_logs[chat_list.get(tk.ACTIVE)].insert(tk.END, current_time + "\n\n", "small")
                    chat_logs[chat_list.get(tk.ACTIVE)].config(state=tk.DISABLED)
                    chat_logs[chat_list.get(tk.ACTIVE)].yview(tk.END)
                    link_window.destroy()
                    if attachment_window is not None:
                        # Close the attachment window
                        attachment_window.destroy()
                else:
                    messagebox.showerror("Error", "No chat selected.")
            elif user_status == "USER_OFFLINE":
                messagebox.showinfo("Error", f"The user {recipient_username} is not online.")

    send_link_button = tk.Button(link_window, text="Send Link", command=send_link, font=font_big, bg="light gray")
    send_link_button.pack(expand=True, fill=tk.BOTH)


# this function is to open the link that was clicked in the chat log and open it in the browser
def handle_link_click(event):
    index = chat_logs[chat_list.get(tk.ACTIVE)].index(tk.CURRENT)
    line = chat_logs[chat_list.get(tk.ACTIVE)].get(f"{index} linestart", f"{index} lineend")
    if "LINK:" in line:
        link = line.split("LINK:", 1)[1].strip()
        webbrowser.open_new_tab(link)


# this function is to start a recording of a voice message
def start_recording():
    global recording, frames, p, stream
    recording = True
    frames = []

    p = pyaudio.PyAudio()

    stream = p.open(format=pyaudio.paInt16,
                    channels=1,
                    rate=44100,
                    input=True,
                    frames_per_buffer=1024)

    while recording:
        data = stream.read(1024)
        frames.append(data)


# this function is to stop the recording and send it to the client class to be sent to the recipient, and update the sender log
def stop_recording():
    global recording, frames, p, stream
    if recording:
        recording = False

        if stream is not None:
            stream.stop_stream()
            stream.close()

        if p is not None:
            p.terminate()

        current_time_seconds = int(time.time())
        filename = f"output_{current_time_seconds}.wav"
        wf = wave.open(filename, 'wb')
        wf.setnchannels(2)
        if p is not None:
            wf.setsampwidth(p.get_sample_size(pyaudio.paInt16))
        wf.setframerate(23000)
        wf.writeframes(b''.join(frames))
        wf.close()

        # Get the username of the selected chat
        recipient_username = chat_list.get(tk.ACTIVE)

        user_status = ""
        msg_header = ""
        msg_header_end = ""
        if ',' in recipient_username:
            msg_header = "$;AUDIO_CHUNK"
            msg_header_end = "$;END_OF_AUDIO"
            client.send_message(f"$;MESSAGE_CHECK;{username}", recipient_username)
            user_status = offline_queue.get()
        else:
            msg_header = "@;AUDIO_CHUNK"
            msg_header_end = "@;END_OF_AUDIO"
            client.send_message(f"@;MESSAGE_CHECK;{username}", recipient_username)
            user_status = offline_queue.get()

        if user_status == "USER_ONLINE":
            # Send the audio file
            with open(filename, 'rb') as file:
                while True:
                    # Read the file in chunks
                    chunk = file.read(CHUNK_SIZE)
                    if not chunk:
                        # If the chunk is empty, end the loop
                        break
                    # Compute the SHA256 hash of the chunk
                    hash_obj = hashlib.sha256()
                    hash_obj.update(chunk)
                    chunk_hash = hash_obj.hexdigest()

                    chunk_data = base64.b64encode(chunk).decode()
                    # Send the chunk
                    client.send_message(f"{msg_header};{filename};{chunk_data};{username};{chunk_hash}", recipient_username)

            # Send the end of file indicator
            client.send_message(f"{msg_header_end};{filename};{username}", recipient_username)
            print("sent the end of audio indicator in tkinter")
            frames = []

            current_time = time.strftime('%H:%M')
            chat_logs[chat_list.get(tk.ACTIVE)].config(state=tk.NORMAL)
            # Add the "FILE:" prefix and the "link" tag to the link in the sender's chat
            chat_logs[chat_list.get(tk.ACTIVE)].insert(tk.END, f"You: AUDIO: {filename}\n", "link")
            chat_logs[chat_list.get(tk.ACTIVE)].insert(tk.END, current_time + "\n\n")
            chat_logs[chat_list.get(tk.ACTIVE)].config(state=tk.DISABLED)
            chat_logs[chat_list.get(tk.ACTIVE)].yview(tk.END)

        elif user_status == "USER_OFFLINE":
            messagebox.showinfo("Error", f"The user {recipient_username} is not online.")


# this function is to manage the labels and the calling of the voice message functions
def toggle_recording():
    global recording
    if recording:
        stop_recording()
        voice_message_button.config(text="Voice Message", bg="light green")
    else:
        threading.Thread(target=start_recording).start()
        voice_message_button.config(text="Stop Recording", bg="salmon")


# this function is to update the client's log when he logges in with his message and chat history
def update_chat_list():
    print("entered the update_chat_list function")
    while not message_queue.empty():
        current_chat, messages = message_queue.get()

        chat_name = str(current_chat)
        print(f"chat name to add when logging in is: {chat_name}")
        chat_list.insert(tk.END, chat_name)

        chat_log = tk.Text(frame, state='disabled', font=font,
                           yscrollcommand=chat_scrollbar.set)

        chat_log.tag_config("link", foreground="blue", underline=True)
        chat_log.tag_config("hyperlink", foreground="blue", underline=True)

        # Bind the open_file function to the "link" tag
        chat_log.tag_bind("link", "<Button-1>", open_file)
        # Bind the handle_link_click function to the "hyperlink" tag
        chat_log.tag_bind("hyperlink", "<Button-1>", handle_link_click)

        # Add the chat log to the chat_logs dictionary
        chat_logs[chat_name] = chat_log

        print(f"Message format: {messages}")
        for message in messages:
            if len(message) == 8:
                message_id, chat_id, sender, receiver, message_content, time_sent, message_type, filepath = message

                time_sent_struct = time.strptime(time_sent, "%Y-%m-%d %H:%M")
                time_sent_formatted = time.strftime("%H:%M", time_sent_struct)
                time_sent_formatted_to_send = time.strftime("%Y-%m-%d %H:%M", time_sent_struct)

                chat_log.config(state=tk.NORMAL)

                if sender == username:
                    print(f"inserting sent message: {message_content}")
                    print(f"sender: {sender}")
                    print(f"receiver: {receiver}")
                    if message_type == "MESSAGE":
                        print("inserting message")
                        chat_logs[current_chat].insert(tk.END,
                                                       "You: " + message_content + "\n" + time_sent_formatted + "\n\n")
                    elif message_type == "LINK":
                        # Display link in sender's chat log
                        chat_logs[current_chat].insert(tk.END, f"You: LINK: {message_content}\n", "hyperlink")
                        chat_logs[current_chat].insert(tk.END, time_sent_formatted + "\n\n")
                    elif message_type == "FILE":
                        chat_logs[current_chat].insert(tk.END, f"You: FILE: {message_content}\n", "link")
                        chat_logs[current_chat].insert(tk.END, time_sent_formatted + "\n\n")
                    elif message_type == "PHOTO":
                        chat_logs[current_chat].insert(tk.END, f"You: PHOTO: {message_content}\n", "link")
                        image = Image.open(message_content)
                        image = resize_image(image)
                        photo = ImageTk.PhotoImage(image)
                        canvas = tk.Canvas(chat_logs[current_chat], width=image.width, height=image.height)
                        canvas.pack()
                        # Create an image item on the canvas
                        canvas.create_image(0, 0, image=photo, anchor='nw')
                        canvas.image = photo
                        chat_logs[current_chat].window_create(tk.END, window=canvas)

                        chat_logs[current_chat].insert(tk.END, "" + "\n")
                        chat_logs[current_chat].insert(tk.END, time_sent_formatted + "\n\n")
                    elif message_type == "VIDEO":
                        chat_logs[current_chat].insert(tk.END, f"You: VIDEO: {message_content}\n", "link")
                        play_button = tk.Button(chat_logs[current_chat], text="Play",
                                                command=lambda: create_video_player(message_content), font=font, fg="black",
                                                bg="lightblue")
                        chat_logs[current_chat].window_create(tk.END, window=play_button)
                        chat_logs[current_chat].insert(tk.END, time_sent_formatted + "\n\n")
                    elif message_type == "AUDIO":
                        chat_logs[current_chat].insert(tk.END, f"You: AUDIO: {message_content}\n", "link")
                        chat_logs[current_chat].insert(tk.END, time_sent_formatted + "\n\n")

                # If you're the receiver
                else:
                    print(f"inserting received message: {message_content}")
                    print(f"sender: {sender}")
                    print(f"receiver: {receiver}")
                    if message_type == "MESSAGE":
                        chat_logs[current_chat].insert(tk.END,
                                                       sender + ": " + message_content + "\n" + time_sent_formatted + "\n\n")

                    elif message_type == "LINK":
                        # Display link in sender's chat log
                        chat_logs[current_chat].insert(tk.END, f"{sender}: LINK: {message_content}\n", "hyperlink")
                        chat_logs[current_chat].insert(tk.END, time_sent_formatted + "\n\n")

                    elif message_type == "FILE":
                        if filepath != "Empty":
                            chat_logs[current_chat].insert(tk.END, f"{sender}: FILE: {filepath}\n", "link")
                            chat_logs[current_chat].insert(tk.END, time_sent_formatted + "\n\n")
                        else:
                            chat_logs[current_chat].tag_bind("link_save_file", "<Button-1>",
                                                             lambda e: save_file(e, message_content,
                                                                                 os.path.basename(message_content),
                                                                                 receiver, "FILE", time_sent_formatted,
                                                                                 sender, "LOGGING", message_content,
                                                                                 time_sent_formatted_to_send))
                            chat_logs[current_chat].tag_config("link_save_file", foreground="blue", underline=True)
                            chat_logs[current_chat].insert(tk.END,
                                                           f"{sender}: FILE: choose where to save the file: {os.path.basename(message_content)}\n",
                                                           "link_save_file")
                            chat_logs[current_chat].insert(tk.END, time_sent_formatted + "\n\n")

                    elif message_type == "PHOTO":
                        if filepath != "Empty":
                            chat_logs[current_chat].insert(tk.END, f"{sender}: PHOTO: {filepath}\n", "link")
                            image = Image.open(filepath)
                            image = resize_image(image)
                            photo = ImageTk.PhotoImage(image)
                            canvas = tk.Canvas(chat_logs[current_chat], width=image.width, height=image.height)
                            canvas.pack()
                            # Create an image item on the canvas
                            canvas.create_image(0, 0, image=photo, anchor='nw')
                            canvas.image = photo
                            chat_logs[current_chat].window_create(tk.END, window=canvas)

                            chat_logs[current_chat].insert(tk.END, "" + "\n")
                            chat_logs[current_chat].insert(tk.END, time_sent_formatted + "\n\n")
                        else:
                            chat_logs[current_chat].tag_bind("link_save_file", "<Button-1>",
                                                             lambda e: save_file(e, message_content,
                                                                                 os.path.basename(message_content),
                                                                                 receiver, "PHOTO", time_sent_formatted,
                                                                                 sender, "LOGGING", message_content,
                                                                                 time_sent_formatted_to_send))
                            chat_logs[current_chat].tag_config("link_save_file", foreground="blue", underline=True)
                            chat_logs[current_chat].insert(tk.END,
                                                           f"{sender}: PHOTO: choose where to save the file: {os.path.basename(message_content)}\n",
                                                           "link_save_file")
                            image = Image.open(message_content)
                            image = resize_image(image)
                            photo = ImageTk.PhotoImage(image)
                            canvas = tk.Canvas(chat_logs[current_chat], width=image.width, height=image.height)
                            canvas.pack()
                            # Create an image item on the canvas
                            canvas.create_image(0, 0, image=photo, anchor='nw')
                            canvas.image = photo
                            chat_logs[current_chat].window_create(tk.END, window=canvas)

                            chat_logs[current_chat].insert(tk.END, "" + "\n")
                            chat_logs[current_chat].insert(tk.END, time_sent_formatted + "\n\n")

                    elif message_type == "VIDEO":
                        if filepath != "Empty":
                            chat_logs[current_chat].insert(tk.END, f"{sender}: VIDEO: {filepath}\n", "link")
                            play_button = tk.Button(chat_logs[current_chat], text="Play",
                                                    command=lambda: create_video_player(filepath), font=font,
                                                    fg="black", bg="lightblue")
                            chat_logs[current_chat].window_create(tk.END, window=play_button)
                            chat_logs[current_chat].insert(tk.END, time_sent_formatted + "\n\n")
                        else:
                            chat_logs[current_chat].tag_bind("link_save_file", "<Button-1>",
                                                             lambda e: save_file(e, message_content,
                                                                                 os.path.basename(message_content),
                                                                                 receiver, "VIDEO", time_sent_formatted,
                                                                                 sender, "LOGGING", message_content,
                                                                                 time_sent_formatted_to_send))
                            chat_logs[current_chat].tag_config("link_save_file", foreground="blue", underline=True)
                            chat_logs[current_chat].insert(tk.END,
                                                           f"{sender}: VIDEO: choose where to save the file: {os.path.basename(message_content)}\n",
                                                           "link_save_file")
                            play_button = tk.Button(chat_logs[current_chat], text="Play",
                                                    command=lambda: create_video_player(message_content), font=font,
                                                    fg="black", bg="lightblue")
                            chat_logs[current_chat].window_create(tk.END, window=play_button)
                            chat_logs[current_chat].insert(tk.END, time_sent_formatted + "\n\n")

                    elif message_type == "AUDIO":
                        if filepath != "Empty":
                            chat_logs[current_chat].insert(tk.END, f"{sender}: AUDIO: {filepath}\n", "link")
                            chat_logs[current_chat].insert(tk.END, time_sent_formatted + "\n\n")
                        else:
                            chat_logs[current_chat].tag_bind("link_save_file", "<Button-1>",
                                                             lambda e: save_file(e, message_content,
                                                                                 os.path.basename(message_content),
                                                                                 receiver, "AUDIO", time_sent_formatted,
                                                                                 sender, "LOGGING", message_content,
                                                                                 time_sent_formatted_to_send))
                            chat_logs[current_chat].tag_config("link_save_file", foreground="blue", underline=True)
                            chat_logs[current_chat].insert(tk.END,
                                                           f"{sender}: AUDIO: choose where to save the file: {os.path.basename(message_content)}\n",
                                                           "link_save_file")
                            chat_logs[current_chat].insert(tk.END, time_sent_formatted + "\n\n")

                chat_log.config(state=tk.DISABLED)
                chat_log.yview(tk.END)
            else:
                print(f"Unexpected message format: {message}")


# this function is to update the chat in the recipient end with any type of message
def update_chat():
    while not message_queue.empty():
        msg = message_queue.get()
        current_time = time.strftime('%H:%M')
        print(msg)
        time_sent = time.strftime('%Y-%m-%d %H:%M')
        print(time_sent)
        print(f"message in update_chat is: {msg}")
        sender_username = msg.split(";", 2)[0]
        recipient_username = msg.split(";", 2)[1]
        # Split the message into sender and message
        message = msg.split(";", 2)[2]

        print(f"sender_username is in update chat: {sender_username}")
        print(f"receiver_username is in update chat: {recipient_username}")

        chat_logs[recipient_username].config(state=tk.NORMAL)
        where_to_put = ""
        if ',' in recipient_username:
            where_to_put = sender_username
        else:
            where_to_put = recipient_username
        if message.startswith("FILE:"):
            # Split the message into command and filename
            filename = message.split(": ", 1)[1].strip()

            full_path = os.path.join(r"C:\Users\Public", os.path.basename(filename))
            chat_logs[recipient_username].tag_bind("link_save_file", "<Button-1>",
                                                   lambda e: save_file(e, full_path, os.path.basename(filename),
                                                                       sender_username, "FILE", current_time,
                                                                       recipient_username, "LOGGING", filename,
                                                                       time_sent))
            chat_logs[recipient_username].tag_config("link_save_file", foreground="blue", underline=True)

            chat_logs[recipient_username].insert(tk.END,
                                                 f"{where_to_put}: FILE: choose where to save the file: {os.path.basename(filename)}\n",
                                                 "link_save_file")
            chat_logs[recipient_username].insert(tk.END, current_time + "\n\n")

        elif message.startswith("PHOTO:"):
            # Split the message into command and filename
            filename = message.split(": ", 1)[1].strip()

            full_path = os.path.join(r"C:\Users\Public", os.path.basename(filename))
            chat_logs[recipient_username].tag_bind("link_save_file", "<Button-1>",
                                                   lambda e: save_file(e, full_path, os.path.basename(filename),
                                                                       sender_username, "PHOTO", current_time,
                                                                       recipient_username, "LOGGING", filename,
                                                                       time_sent))
            chat_logs[recipient_username].tag_config("link_save_file", foreground="blue", underline=True)

            chat_logs[recipient_username].insert(tk.END,
                                                 f"{where_to_put}: PHOTO: choose where to save the file: {os.path.basename(filename)}\n",
                                                 "link_save_file")
            image = Image.open(full_path)
            image = resize_image(image)
            photo = ImageTk.PhotoImage(image)
            canvas = tk.Canvas(chat_logs[recipient_username], width=image.width, height=image.height)
            canvas.pack()
            # Create an image item on the canvas
            canvas.create_image(0, 0, image=photo, anchor='nw')
            canvas.image = photo
            chat_logs[recipient_username].window_create(tk.END, window=canvas)

            chat_logs[chat_list.get(tk.ACTIVE)].insert(tk.END, "" + "\n")
            chat_logs[recipient_username].insert(tk.END, current_time + "\n\n")

        elif message.startswith("VIDEO:"):
            # Split the message into command and filename
            filename = message.split(": ", 1)[1].strip()

            full_path = os.path.join(r"C:\Users\Public", os.path.basename(filename))
            chat_logs[recipient_username].tag_bind("link_save_file", "<Button-1>",
                                                   lambda e: save_file(e, full_path, os.path.basename(filename),
                                                                       sender_username, "VIDEO", current_time,
                                                                       recipient_username, "LOGGING", filename,
                                                                       time_sent))
            chat_logs[recipient_username].tag_config("link_save_file", foreground="blue", underline=True)

            chat_logs[recipient_username].insert(tk.END,
                                                 f"{where_to_put}: VIDEO: choose where to save the file: {os.path.basename(filename)}\n",
                                                 "link_save_file")
            play_button = tk.Button(chat_logs[recipient_username], text="Play",
                                    command=lambda: create_video_player(full_path), font=font, fg="black",
                                    bg="lightblue")
            chat_logs[recipient_username].window_create(tk.END, window=play_button)
            chat_logs[recipient_username].insert(tk.END, current_time + "\n\n")

        elif message.startswith("AUDIO:"):
            # Split the message into command and filename
            filename = message.split(": ", 1)[1].strip()

            full_path = os.path.join(r"C:\Users\Public", os.path.basename(filename))
            chat_logs[recipient_username].tag_bind("link_save_file", "<Button-1>",
                                                   lambda e: save_file(e, full_path, os.path.basename(filename),
                                                                       sender_username, "AUDIO", current_time,
                                                                       recipient_username, "LOGGING", filename,
                                                                       time_sent))
            chat_logs[recipient_username].tag_config("link_save_file", foreground="blue", underline=True)

            chat_logs[recipient_username].insert(tk.END,
                                                 f"{where_to_put}: AUDIO: choose where to save the file: {os.path.basename(filename)}\n",
                                                 "link_save_file")
            chat_logs[recipient_username].insert(tk.END, current_time + "\n\n")

        elif message.startswith("LINK:"):
            print("updating chat with link")
            # Split the message into command and filename
            link_name = message.split(':', 1)[1]
            # Add the "FILE:" prefix and the "link" tag to the link
            chat_logs[recipient_username].insert(tk.END, f"{where_to_put}: LINK: {link_name}\n", "hyperlink")
            chat_logs[recipient_username].insert(tk.END, current_time + "\n\n")

        elif message.startswith("MESSAGE:"):
            message_content = message.split(": ", 1)[1]
            print("inserting text message in update_chat")
            chat_logs[recipient_username].insert(tk.END, f"{where_to_put}: {message_content}\n")
            chat_logs[recipient_username].insert(tk.END, current_time + "\n\n")
        chat_logs[recipient_username].config(state=tk.DISABLED)
        chat_logs[recipient_username].yview(tk.END)
    # Check for new messages every 100ms
    root.after(100, update_chat)


# this function closes the window when called
def close_window():
    # Close the client connection
    client.close_program()
    # Terminate the entire Python process
    os._exit(0)


def toggle_send_button(event):
    # Check if the message box is empty
    if message_entry.get():
        # If the message box is not empty, show the send button
        send_button.pack(side=tk.LEFT, fill=tk.X)
    else:
        # If the message box is empty, hide the send button
        send_button.pack_forget()


# Start checking for new messages
root.after(100, update_chat)
# Start checking for new messages
root.after(100, handle_delete_chat)

chat_count = 0
chat_logs = {}

root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=2)

frame = tk.Frame(root)
frame.grid(row=0, column=1, sticky="nsew")

# create the chat frame
chat_frame = tk.Frame(root)
chat_frame.grid(row=0, column=0, sticky="nsew")

# create the button frame
button_frame = tk.Frame(chat_frame)
button_frame.pack(side=tk.TOP, fill=tk.X)

button_and_list_frame = tk.Frame(chat_frame)
button_and_list_frame.pack(side=tk.TOP, fill=tk.BOTH)

# create the user info label
user_info_label = tk.Label(button_and_list_frame, text="", font=font, bg="light green")
user_info_label.pack(side=tk.TOP, fill=tk.X)

# create the buttons for new chat, delete chat and for new group
new_chat_button = tk.Button(button_and_list_frame, text="New Chat", command=create_new_chat, font=font, bg="light green")
new_chat_button.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

delete_chat_button = tk.Button(button_and_list_frame, text="Delete Chat", command=delete_chat, font=font, bg="light green")
delete_chat_button.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

new_group_button = tk.Button(button_and_list_frame, text="New Group", command=create_group_chat, font=font, bg="light green")
new_group_button.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

chat_list = tk.Listbox(chat_frame, font=font, selectbackground='light gray', selectforeground='black')
chat_list.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
chat_list.bind('<<ListboxSelect>>', switch_chat)

# create the message frame, and the message box, attachment button, send button and voice message button
message_frame = tk.Frame(frame)
message_frame.pack(side=tk.BOTTOM, fill=tk.X)

attachment_button = tk.Button(message_frame, text="Attachment", command=open_attachment_window, state=tk.DISABLED, font=font, bg="light green")
attachment_button.pack(side=tk.LEFT, fill=tk.X)

voice_message_button = tk.Button(message_frame, text="Voice Message", command=toggle_recording, state=tk.DISABLED, font=font, bg="light green")
voice_message_button.pack(side=tk.LEFT, fill=tk.X)

message_entry = tk.Entry(message_frame, font=font, state=tk.DISABLED)
message_entry.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
# Bind the function to the KeyRelease event of the message box
message_entry.bind('<KeyRelease>', toggle_send_button)

send_button = tk.Button(message_frame, text="Send", command=send_message_in_tkinter, font=font, state=tk.DISABLED, bg="light green")
send_button.pack(side=tk.LEFT, fill=tk.X)
# Initially hide the send button
send_button.pack_forget()


# make it send messages when pressed Return
root.bind('<Return>', lambda event: send_message_in_tkinter())

chat_label = tk.Label(frame, text="", font=font)
chat_label.pack(side=tk.TOP, fill=tk.X)


# for the scroll bar functionality
def yview(*args):
    for chat_log in chat_logs.values():
        chat_log.yview(*args)


# create a scroll bar for the frame
chat_scrollbar = tk.Scrollbar(frame, command=yview)
chat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

root.protocol("WM_DELETE_WINDOW", close_window)

# Start checking for new messages in the recipient end
root.after(100, update_chat)

check_new_group_queue()
# run the main loop of the tkInter class
root.mainloop()
