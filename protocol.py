LENGTH = 8

CHUNK_SIZE = 4096


# this function get a socket and a message and sends the message to the socket with a header of the len of chars in the message
def send(socket, msg):
    msg_len = str(len(msg)).zfill(LENGTH)
    msg_to_send = (msg_len + msg).encode("utf-8")
    # send the data with the header to the socket
    socket.send(msg_to_send)


# this function gets a socket and receives the message that is sent to the socket and returns it
def receive(socket):
    try:
        # receive the length of the message
        msg_len = socket.recv(LENGTH).decode("utf-8")
        if msg_len != '':
            if int(msg_len) > 0:
                msg_len_int = int(msg_len)
                msg = ''
                while len(msg) < msg_len_int:
                    # Read bytes
                    bytes_to_read = min(msg_len_int - len(msg), CHUNK_SIZE)
                    data = socket.recv(bytes_to_read).decode("utf-8")
                    msg += data
                return msg
    except ConnectionResetError:
        print("A client has disconnected.")
        return None

    except Exception as e:
        print(f"[ERROR] Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return None
