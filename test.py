import os
import tkinter as tk
from tkinter import *
from tkinter import filedialog
from PIL import ImageTk, Image
import cv2


def create_video_player(filename):
    # Create a new Tkinter window
    video_play_window = tk.Toplevel()

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
        play_stop_button.config(text="Play", command=stream_video1)

    def stream_video1():
        global stop_flag
        stop_flag = False
        stream_video()
        play_stop_button.config(text="Stop", command=stop_video)

    def close_video_window():
        os._exit(0)

    # Create a button that stops the video when clicked
    play_stop_button = tk.Button(
        video_play_window,  # the window the button will be added to
        text="Play",  # the text on the button
        font=("Arial", 24),  # the font and size of the text
        fg="black",  # the color of the text (fg stands for foreground)
        bg="lightblue",  # the color of the button (bg stands for background)
        width=10,  # the width of the button (in characters)
        height=2,  # the height of the button (in lines of text)
        command=stream_video1  # the function to call when the button is clicked
    )
    play_stop_button.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

    # Create a button that stops the video when clicked
    close_window = tk.Button(
        video_play_window,  # the window the button will be added to
        text="Close Window",  # the text on the button
        font=("Arial", 24),  # the font and size of the text
        fg="black",  # the color of the text (fg stands for foreground)
        bg="lightblue",  # the color of the button (bg stands for background)
        width=10,  # the width of the button (in characters)
        height=2,  # the height of the button (in lines of text)
        command=close_video_window  # the function to call when the button is clicked
    )
    close_window.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

    # Start the Tkinter event loop
    video_play_window.mainloop()


filename = filedialog.askopenfilename(filetypes=[('Video Files', '*.mp4 *.avi *.mov *.flv *.mkv')])
create_video_player(filename)

#
# from tkinter import Tk, Canvas, filedialog
# from PIL import Image, ImageTk
#
#
# def resize_image(image, max_width=300, max_height=240):
#     image_width = image.width
#     image_height = image.height
#
#     # If the image is horizontal
#     if image_width > image_height:
#         if image_width > max_width:
#             # Calculate the ratio of the new width to the original width
#             ratio = max_width / float(image_width)
#             # Calculate the new height based on the ratio
#             image_height = int(image_height * ratio)
#             # Set the width to the maximum width
#             image_width = max_width
#     else:  # If the image is vertical
#         if image_height > max_height:
#             # Calculate the ratio of the new height to the original height
#             ratio = max_height / float(image_height)
#             # Calculate the new width based on the ratio
#             image_width = int(image_width * ratio)
#             # Set the height to the maximum height
#             image_height = max_height
#
#     # Resize the image
#     image = image.resize((image_width, image_height))
#
#     return image
#
#
# root = Tk()
#
# filename = filedialog.askopenfilename(
#     filetypes=[('Image Files', '*.png *.jpg *.jpeg *.gif')])
#
# image = Image.open(filename)
#
# # Call the resize_image function
# image = resize_image(image)
#
# canvas = Canvas(root, width=image.width, height=image.height)
# canvas.pack()
#
# photo = ImageTk.PhotoImage(image)
# canvas.create_image(0, 0, image=photo, anchor='nw')
#
# root.mainloop()

# import socket
# import json
# import ssl
#
# my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# my_socket.connect(('127.0.0.1', 9999))
# print('c1')
#
#
# while True:
#     op = input("for sign-up type s, for login type l, for exit type something else: \r\n ")
#     if op == "s" or op == "l":
#         username = input("please enter username:  ")
#         password = input("please enter password:  ")
#         # msg = json.dumps({'op':op, 'username':username, 'password':password})
#         # msg = op + ',' + username + ','+password
#         msg = f"{op},{username},{password}"
#         my_socket.send(msg.encode())
#         data = my_socket.recv(1024)
#         print (data.decode())
#     else:
#         my_socket.send(json.dumps({'op':'q'}).encode())
#         break
#
# my_socket.close()
#
#
# import socket
# import threading
# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP, AES
# from Crypto.Util.Padding import pad, unpad
# from Crypto.Random import get_random_bytes
# import base64
# import protocol
#
#
# client_socket = None
# # rsa_public_key = None
#
#
# def generate_key():
#     # Generate a random 256-bit (32-byte) AES key
#     return get_random_bytes(32)
#
#
# def generate_iv():
#     # Generate a random 128-bit (16-byte) IV
#     return get_random_bytes(16)
#
#
# def generate_rsa_keys():
#     # Generate RSA keys
#     sender_rsa_key = RSA.generate(2048)
#     sender_rsa_public_key = sender_rsa_key.publickey()
#     return sender_rsa_key, sender_rsa_public_key
#
#
# def aes_encrypt(plaintext, key, iv):
#     # Create an AES cipher object with the provided key, AES.MODE_CBC mode, and the given IV
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#
#     # Pad the plaintext to match the block size (128 bits or 16 bytes for AES)
#     padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
#
#     # Encrypt the padded plaintext
#     ciphertext = cipher.encrypt(padded_plaintext)
#
#     return ciphertext
#
#
# def aes_decrypt(ciphertext, key, iv):
#     # Create an AES cipher object with the provided key, AES.MODE_CBC mode, and the given IV
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#
#     # Decrypt the ciphertext
#     decrypted_data = cipher.decrypt(ciphertext)
#
#     # Un pad the decrypted data
#     plaintext = unpad(decrypted_data, AES.block_size)
#
#     return plaintext.decode('utf-8')
#
#
# def encode_message(client_socket, message):
#     try:
#         protocol.send(client_socket, "GET_PUBLIC_KEY")
#         print("sent the get public key")
#         response = protocol.receive(client_socket)
#         print(f"response = {response}")
#         rsa_public_key_pem = response.split(";", 1)[1]
#         print(type(rsa_public_key_pem))
#         rsa_public_key = RSA.import_key(rsa_public_key_pem)
#         print(type(rsa_public_key))
#
#         # Generate a random AES key and IV
#         encryption_key = generate_key()
#         iv = generate_iv()
#
#         # Encrypt the AES key and IV using RSA
#         cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
#         encrypted_aes_key_send = cipher_rsa.encrypt(encryption_key)
#         encrypted_iv_send = cipher_rsa.encrypt(iv)
#
#         # Encrypt the message using AES
#         encrypted_message = aes_encrypt(message, encryption_key, iv)
#
#         encrypted_aes_key_send_b64 = base64.b64encode(encrypted_aes_key_send).decode()
#         encrypted_iv_send_b64 = base64.b64encode(encrypted_iv_send).decode()
#         encrypted_message_b64 = base64.b64encode(encrypted_message).decode()
#
#         return encrypted_aes_key_send_b64, encrypted_iv_send_b64, encrypted_message_b64
#     except Exception as e:
#         print(f"[ERROR] Exception: {str(e)}")
#         import traceback
#         traceback.print_exc()
#
#
# def decode_message(rsa_key, data):
#     tag, encrypted_aes_key_b64, encrypted_iv_b64, encrypted_message_b64 = data.split(";")
#
#     encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
#     encrypted_iv = base64.b64decode(encrypted_iv_b64)
#     encrypted_message = base64.b64decode(encrypted_message_b64)
#
#     # Decrypt the AES key and IV using RSA
#     cipher_rsa = PKCS1_OAEP.new(rsa_key)
#     decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
#     decrypted_iv = cipher_rsa.decrypt(encrypted_iv)
#
#     print(f"encrypted message: {encrypted_message}")
#
#     # Decrypt the message using AES
#     cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CBC, decrypted_iv)
#     decrypted_message = unpad(cipher_aes.decrypt(encrypted_message), AES.block_size)
#
#     return decrypted_message
#
#
# def send_message():
#     # Encrypt the message using AES
#     plaintext_message = input("Enter a message to encrypt: ")
#     encrypted_aes_key_send_b64, encrypted_iv_send_b64, encrypted_message_b64 = encode_message(client_socket, plaintext_message)
#     protocol.send(client_socket, f"MESSAGE;{encrypted_aes_key_send_b64};{encrypted_iv_send_b64};{encrypted_message_b64}")
#
#
# def receive_message(client_socket, rsa_key):
#     data = protocol.receive(client_socket)
#     decrypted_message = decode_message(rsa_key, data)
#     print(f"Decrypted Message: {decrypted_message.decode()}")
#
#     # Close the socket
#     client_socket.close()
#
#
# def main():
#     global client_socket
#     client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     client_socket.connect(('localhost', 12345))
#
#     # Generate RSA keys
#     rsa_key, rsa_public_key = generate_rsa_keys()
#     rsa_public_key_pem = rsa_public_key.export_key().decode()
#     protocol.send(client_socket, f"ADD_PUBLIC_KEY;{rsa_public_key_pem}")
#     response = protocol.receive(client_socket)
#
#     if response.startswith("ADDED_PUBLIC_KEY"):
#         send_message()
#         receive_thread = threading.Thread(target=receive_message, args=(client_socket, rsa_key))
#         receive_thread.start()
#
#
# if __name__ == "__main__":
#     main()
# import hashlib
# chunk = b"hi"
# hash_obj = hashlib.sha256()
# hash_obj.update(chunk)
# computed_hash = hash_obj.hexdigest()
# print(computed_hash)
