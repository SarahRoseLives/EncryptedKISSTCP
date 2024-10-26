import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import threading

# APRS KISS settings
DIGI_PATH = ["WIDE1-1", "WIDE2-1"]  # Digipeater path

# Hardcoded encryption key
ENCRYPTION_KEY = 'my_secret_key'  # Change this key as needed

def ax25_encode_callsign(callsign, is_last=False):
    callsign, ssid = (callsign.split("-") + ["0"])[:2]  # Split into base and SSID, default to SSID=0
    callsign = callsign.upper().ljust(6)  # Ensure it's 6 characters, padded with spaces

    encoded = bytearray([ord(c) << 1 for c in callsign[:6]])  # Shift left ASCII codes

    ssid = int(ssid) & 0x0F  # SSID can only be in the range of 0-15
    ssid_byte = (ssid << 1) | 0x60  # Set bits 0-3 to 1 (APRS) and Bit 6-7 for SSID
    if is_last:
        ssid_byte |= 0x01  # Mark the last callsign (L-bit)

    encoded.append(ssid_byte)

    return encoded

def ax25_create_frame(source, digipeaters, message):
    frame = bytearray()
    frame.extend(ax25_encode_callsign(source))  # Use dynamic source callsign

    for i, digi in enumerate(digipeaters):
        is_last_digi = (i == len(digipeaters) - 1)
        frame.extend(ax25_encode_callsign(digi, is_last=is_last_digi))

    frame.extend([0x03, 0xF0])  # Control byte for UI frame and PID byte for no layer 3 protocol
    frame.extend(message.encode('ascii'))

    return frame

def kiss_encode(ax25_frame):
    kiss_frame = bytearray([0xC0])  # Start with the KISS frame delimiter
    kiss_frame.append(0x00)  # KISS data frame indicator

    for byte in ax25_frame:
        if byte == 0xC0:  # Frame delimiter, must be escaped
            kiss_frame.extend([0xDB, 0xDC])
        elif byte == 0xDB:  # Escape byte, must be escaped
            kiss_frame.extend([0xDB, 0xDD])
        else:
            kiss_frame.append(byte)

    kiss_frame.append(0xC0)  # End the frame with the closing delimiter
    return bytes(kiss_frame)

def kiss_decode(kiss_frame):
    if kiss_frame[0] != 0xC0 or kiss_frame[-1] != 0xC0:
        raise ValueError("Invalid KISS frame delimiters")

    ax25_frame = bytearray()
    i = 1  # Start after the initial 0xC0
    while i < len(kiss_frame) - 1:
        if kiss_frame[i] == 0xDB:  # Escape sequence
            if kiss_frame[i + 1] == 0xDC:
                ax25_frame.append(0xC0)  # Restore frame delimiter
            elif kiss_frame[i + 1] == 0xDD:
                ax25_frame.append(0xDB)  # Restore escape byte
            i += 2
        else:
            ax25_frame.append(kiss_frame[i])
            i += 1
    return ax25_frame

def extract_aprs_message(ax25_frame):
    num_callsigns = 1 + len(DIGI_PATH)  # 1 for source, plus digipeaters
    start_of_message = 7 * num_callsigns + 2  # +2 to skip the control and PID bytes
    aprs_message = ax25_frame[start_of_message:].decode('ascii', errors='ignore')
    return aprs_message

def extract_callsigns(ax25_frame):
    num_callsigns = 1 + len(DIGI_PATH)  # 1 for source, plus digipeaters
    callsigns = []

    for i in range(num_callsigns):
        callsign_bytes = ax25_frame[i * 7: (i + 1) * 7]
        callsign = ''.join(chr((b >> 1) & 0x7F) for b in callsign_bytes[:6]).rstrip()
        callsign = callsign.lstrip()  # Remove leading spaces
        callsign = ''.join(c for c in callsign if c.isprintable())  # Keep only printable characters

        ssid = callsign_bytes[6] & 0x0F  # Get SSID from the last byte
        if ssid:
            callsign += f"-{ssid}"

        callsigns.append(callsign)

    return callsigns

def encrypt_message(message):
    """Encrypts the message using a simple XOR encryption with a hardcoded key."""
    return ''.join(chr(ord(c) ^ ord(ENCRYPTION_KEY[i % len(ENCRYPTION_KEY)])) for i, c in enumerate(message))

def decrypt_message(encrypted_message):
    """Decrypts the message using a simple XOR decryption with a hardcoded key."""
    return ''.join(chr(ord(c) ^ ord(ENCRYPTION_KEY[i % len(ENCRYPTION_KEY)])) for i, c in enumerate(encrypted_message))

def send_kiss_message(sock, source_call, message):
    try:
        encrypted_message = encrypt_message(message)  # Encrypt the message before sending
        ax25_frame = ax25_create_frame(source_call, DIGI_PATH, encrypted_message)
        kiss_frame = kiss_encode(ax25_frame)
        sock.sendall(kiss_frame)
        print(f"Sent APRS message: {source_call}> {message}")
    except Exception as e:
        print(f"Error sending message: {e}")

def receive_kiss_messages(sock, chat_area):
    buffer = bytearray()
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                break  # Connection closed
            buffer.extend(data)

            while 0xC0 in buffer:
                start = buffer.index(0xC0)
                if buffer.count(0xC0) >= 2:
                    end = buffer.index(0xC0, start + 1)
                    kiss_frame = buffer[start:end + 1]
                    buffer = buffer[end + 1:]

                    ax25_frame = kiss_decode(kiss_frame)
                    encrypted_aprs_message = extract_aprs_message(ax25_frame)
                    callsigns = extract_callsigns(ax25_frame)

                    decrypted_aprs_message = decrypt_message(encrypted_aprs_message)  # Decrypt the message

                    chat_area.config(state='normal')
                    chat_area.insert(tk.END, f"{callsigns[0]}> {decrypted_aprs_message}\n")  # Display only sender's callsign
                    chat_area.config(state='disabled')

                else:
                    break

        except Exception as e:
            print(f"Error receiving message: {e}")
            break

class ChatApp:
    def __init__(self, root, sock):
        self.root = root
        self.sock = sock
        self.root.title("Chat Application")

        # Create a text area for displaying chat messages
        self.chat_area = scrolledtext.ScrolledText(self.root, state='disabled', wrap='word', height=15)
        self.chat_area.pack(padx=10, pady=(10, 0), fill='both', expand=True)

        # Create a frame for username and message entry at the bottom
        self.input_frame = tk.Frame(self.root)
        self.input_frame.pack(pady=10, fill='x')

        # Username entry
        tk.Label(self.input_frame, text="Username:").pack(side=tk.LEFT)
        self.username_entry = tk.Entry(self.input_frame, width=15)
        self.username_entry.pack(side=tk.LEFT)

        # Message entry
        self.entry_field = tk.Entry(self.input_frame, width=50)
        self.entry_field.pack(side=tk.LEFT, padx=(5, 0))
        self.entry_field.bind('<Return>', self.send_message)

        # Create a send button
        self.send_button = tk.Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=(5, 0))

        # Start a thread to receive messages
        self.receive_thread = threading.Thread(target=receive_kiss_messages, args=(self.sock, self.chat_area), daemon=True)
        self.receive_thread.start()

    def send_message(self, event=None):
        username = self.username_entry.get() or "Guest"
        message = self.entry_field.get()
        if message:
            send_kiss_message(self.sock, username, message)  # Use dynamic username as source
            self.chat_area.config(state='normal')
            self.chat_area.insert(tk.END, f"{username}> {message}\n")  # Display sent message format
            self.chat_area.config(state='disabled')
            self.entry_field.delete(0, tk.END)  # Clear the message entry

# Main function to set up the socket and launch the application
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 8002))  # Change to your APRS server address and port

    root = tk.Tk()
    chat_app = ChatApp(root, sock)
    root.protocol("WM_DELETE_WINDOW", root.quit)  # Handle window close event
    root.mainloop()

    sock.close()

if __name__ == "__main__":
    main()
