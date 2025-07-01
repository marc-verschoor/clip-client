Subject:
clip_client
From:
VERSCHOOR Marc <marc.verschoor@ayvens.com>
Date:
7/1/25, 10:34
To:
Marc Verschoor <marc.j.verschoor@gmail.com>


import socket
import threading
import argparse
import sys
import platform
import time
import pyperclip
import signal
import base64
import os
import struct
from pathlib import Path
from datetime import datetime
from queue import Queue

# Default configuration
DEFAULT_PORT = 5000
BUFFER_SIZE = 10 * 1024 * 1024
CLIPBOARD_CHECK_INTERVAL = 1  # seconds
POLLING_INTERVAL = 5         # seconds
HEADER_SIZE = 4              # 4 bytes for message length



class ClipboardSharer:
    def __init__(self, host_ip, connect_to, port, nickname, watch_dir=None):
        self.shared_clipboard = ""
        self.connected_clients = []  # Each item: (client_address, client_socket)
        self.server_socket = None
        self.local_ip = host_ip
        self.connect_to = connect_to
        self.port = port
        self.nickname = nickname if nickname else "Unknown"
        self.stop_event = threading.Event()
        self.ignore_next_clipboard_change = False
        self.client_nicknames = {}  # Map client addresses to nicknames
        self.watch_dir = watch_dir  # For macOS directory monitoring

        # Set up networking and monitoring:
        self.start_server()
        self.connect_to_specified_hosts()
        self.monitor_clipboard()
        if self.watch_dir and sys.platform == "darwin":
            self.monitor_directory(self.watch_dir)
        self.poll_for_updates()

        print("ClipboardSharer initialized successfully.")

    def recvall(self, sock, n):
        """Helper function to receive exactly n bytes or return None."""
        data = bytearray()
        while len(data) < n and not self.stop_event.is_set():
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def handle_client(self, client_socket, client_address):
        """Receive data from a connected client and update the clipboard or save a file
           using a 4-byte length-prefixed message framing protocol.
        """
        try:
            while not self.stop_event.is_set():
                header = self.recvall(client_socket, HEADER_SIZE)
                if not header:
                    break
                msg_length = struct.unpack('!I', header)[0]
                message_bytes = self.recvall(client_socket, msg_length)
                if not message_bytes:
                    break
                try:
                    received_content = message_bytes.decode('utf-8')
                except UnicodeDecodeError as ude:
                    print(f"Decoding error from {client_address}: {ude}")
                    continue

                # Check for file transfer message.
                if received_content.startswith("FILE:"):
                    # Expected format: FILE:{filename}:{b64_data}
                    try:
                        parts = received_content.split(":", 2)
                        if len(parts) != 3:
                            raise ValueError("Invalid file message format")
                        filename = parts[1]
                        b64_data = parts[2]
                        file_data = base64.b64decode(b64_data)
                        download_dir = Path.home() / "Downloads"
                        download_dir.mkdir(parents=True, exist_ok=True)
                        file_path = download_dir / filename
                        with open(file_path, "wb") as f:
                            f.write(file_data)
                        # Only minimal output on receipt
                        print(f"Received file: {filename}")
                        self.gui_update_queue.put(('text', f"Received file: {filename}"))
                    except Exception as e:
                        print(f"Error processing file transfer from {client_address}: {e}")
                    continue  # Skip further processing for file messages.
                elif received_content.startswith("TEXT:"):
                    # Expected format: TEXT:{nickname}:{clipboard-content}
                    try:
                        parts = received_content.split(":", 2)
                        if len(parts) != 3:
                            raise ValueError("Invalid text message format")
                        source = parts[1]
                        clipboard_content = parts[2]
                    except ValueError:
                        source = client_address[0]
                        clipboard_content = received_content
                else:
                    # Fallback behavior for compatibility with older messages.
                    try:
                        source, clipboard_content = received_content.split(":", 1)
                    except ValueError:
                        source = client_address[0]
                        clipboard_content = received_content

                if clipboard_content != self.shared_clipboard:
                    self.ignore_next_clipboard_change = True
                    pyperclip.copy(clipboard_content)
                    self.shared_clipboard = clipboard_content
                    print(f"Updating clipboard from source: {source}")
        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()
            if (client_address, client_socket) in self.connected_clients:
                self.connected_clients.remove((client_address, client_socket))
            print(f"Connection closed with {client_address}")

    def start_server(self):
        """Start a server socket to accept incoming connections."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.local_ip, self.port))
            self.server_socket.listen(5)
            print(f"Server listening on {self.local_ip}:{self.port}")
            threading.Thread(target=self.accept_connections, daemon=True).start()
        except Exception as e:
            print(f"Error starting server: {e}")

    def accept_connections(self):
        """Accept incoming client connections."""
        while not self.stop_event.is_set():
            try:
                client_socket, client_address = self.server_socket.accept()
                print(f"Accepted connection from {client_address}")
                self.connected_clients.append((client_address, client_socket))
                threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True).start()
            except OSError as e:
                if e.errno == 9:
                    print("Server socket closed, stopping accept loop.")
                    break
                else:
                    print(f"Error accepting connections: {e}")

    def connect_to_specified_hosts(self):
        """Attempt connections to hosts provided on the command line."""
        for host in self.connect_to:
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((host, self.port))
                self.connected_clients.append(((host, self.port), client_socket))
                print(f"Connected to {host}:{self.port}")
                threading.Thread(target=self.handle_client, args=(client_socket, (host, self.port)), daemon=True).start()
                self.update_tray_icon()
            except Exception as e:
                print(f"Error connecting to {host}:{self.port} - {e}")

    def get_clipboard_content_win32(self):
        """Retrieve clipboard content using win32clipboard for Windows.
           If clipboard contains file paths (CF_HDROP), return the first file path.
        """
        try:
            import win32clipboard
            import win32con
        except ImportError:
            print("win32clipboard not installed; falling back to pyperclip.")
            return pyperclip.paste()
        win32clipboard.OpenClipboard()
        try:
            if win32clipboard.IsClipboardFormatAvailable(win32con.CF_HDROP):
                data = win32clipboard.GetClipboardData(win32con.CF_HDROP)
                if data:
                    # Return the full file path of the first file copied
                    return data[0]
            elif win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                data = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
                return data
        except Exception as e:
            print(f"Error accessing Windows clipboard: {e}")
        finally:
            win32clipboard.CloseClipboard()
        return ""

    def monitor_clipboard(self):
        """Continuously monitor the clipboard for changes."""
        def clipboard_check():
            while not self.stop_event.is_set():
                try:
                    current_clipboard_content = pyperclip.paste()
                    if current_clipboard_content != self.shared_clipboard:
                        if self.ignore_next_clipboard_change:
                            self.ignore_next_clipboard_change = False
                        else:
                            self.shared_clipboard = current_clipboard_content
                            print(f"Clipboard updated: {self.shared_clipboard}")
                            self.notify_clients()
                except Exception as e:
                    print(f"Error monitoring clipboard: {e}")
                finally:
                    self.stop_event.wait(CLIPBOARD_CHECK_INTERVAL)
        threading.Thread(target=clipboard_check, daemon=True).start()

    def monitor_directory(self, directory):
        """Monitor a specific directory (macOS) for new files to send.
           This polling-based approach checks for new files every second.
        """
        def directory_check():
            previously_seen = set(os.listdir(directory))
            while not self.stop_event.is_set():
                try:
                    current_files = set(os.listdir(directory))
                    new_files = current_files - previously_seen
                    for filename in new_files:
                        full_path = os.path.join(directory, filename)
                        if os.path.isfile(full_path):
                            # Treat the newly added file as clipboard content and notify clients.
                            self.shared_clipboard = full_path
                            print(f"Detected new file in monitored directory: {filename}")
                            self.notify_clients()
                    previously_seen = current_files
                except Exception as e:
                    print(f"Error monitoring directory '{directory}': {e}")
                finally:
                    self.stop_event.wait(1)
        threading.Thread(target=directory_check, daemon=True).start()

    def notify_clients(self):
        """Send the shared clipboard content to all connected clients.
           If the clipboard content is a valid file path, send the file; otherwise send text.
           The message is framed by a 4-byte header indicating the message length.
        """
        if os.path.isfile(self.shared_clipboard):
            try:
                with open(self.shared_clipboard, "rb") as f:
                    file_data = f.read()
                b64_data = base64.b64encode(file_data).decode('utf-8')
                payload = f"FILE:{os.path.basename(self.shared_clipboard)}:{b64_data}"
                print(f"Sending file: {os.path.basename(self.shared_clipboard)}")
            except Exception as e:
                print(f"Error reading file '{os.path.basename(self.shared_clipboard)}': {e}")
                return
        else:
            payload = f"TEXT:{self.nickname}:{self.shared_clipboard}"

        message_bytes = payload.encode('utf-8')
        header = struct.pack('!I', len(message_bytes))
        framed_message = header + message_bytes

        for _, client_socket in self.connected_clients:
            try:
                client_socket.sendall(framed_message)
            except Exception as e:
                print(f"Error notifying client: {e}")

    def poll_for_updates(self):
        """Periodically poll for updates (debug/logging purposes)."""
        def update_check():
            while not self.stop_event.is_set():
                try:
                    print("Polling for updates...")
                    self.stop_event.wait(POLLING_INTERVAL)
                except Exception as e:
                    print(f"Error polling for updates: {e}")
        threading.Thread(target=update_check, daemon=True).start()

    def quit_application(self):
        """Cleanup and exit the application."""
        print("Exiting ClipboardSharer...")
        self.stop_event.set()
        if self.server_socket:
            try:
                self.server_socket.close()
                print("Server socket closed.")
            except Exception as e:
                print(f"Error closing server socket: {e}")
        for client_address, client_socket in self.connected_clients:
            try:
                client_socket.close()
                print(f"Closed connection with {client_address}")
            except Exception as e:
                print(f"Error closing client socket {client_address}: {e}")
        self.connected_clients.clear()
        sys.exit(0)

    def get_connected_clients_info(self):
        """Return a string of connected client info (nickname or IP)."""
        clients_info = []
        for client_address, _ in self.connected_clients:
            client_nick = self.nickname if self.nickname else client_address[0]
            clients_info.append(client_nick)
        return ', '.join(clients_info)

def get_default_interface_ip() -> str:
    """
    Determine the IP address bound to the default outbound interface.

    This method opens a UDP socket to a well-known external address
    (which never actually sends traffic) purely so the OS selects the
    interface it would use; we then read the locally-bound address.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # The IP/port below is irrelevant; no packets are sent.
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        # Fallback to localhost if every attempt fails.
        return "127.0.0.1"
    finally:
        s.close()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Clipboard Sharer")
    parser.add_argument("--host", help="This machine's IP address. If omitted, it will be auto-detected.")
    parser.add_argument("--connect", nargs="+", default=[], help="List of hostnames or IP addresses to connect to.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port for communication.")
    parser.add_argument("--nick", help="Nickname for this host.")
    # For macOS, allow specifying a directory to monitor for file transfers.
    parser.add_argument("--watch-dir", help="Directory to monitor for new files (macOS only).")
    return parser.parse_args()


if __name__ == "__main__":
    print("Parsing arguments...")
    args = parse_arguments()

    # Auto-detect host IP if not provided
    if not args.host:
        args.host = get_default_interface_ip()
        print(f"No --host supplied; using detected IP: {args.host}")

    # Auto-detect nickname if not provided
    if not args.nick:
        args.nick = platform.node()
        print(f"No --nick supplied; using machine name: {args.nick}")

    print("Initializing ClipboardSharer...")
    clipboard_sharer = ClipboardSharer(args.host, args.connect, args.port, args.nick, watch_dir=args.watch_dir)

    # Set SIGINT handler in the main thread for CTRL+C.
    signal.signal(signal.SIGINT, lambda sig, frame: clipboard_sharer.quit_application())

    # Without UI components, keep the main thread alive with a simple loop.
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        clipboard_sharer.quit_application()

