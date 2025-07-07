import socket
import threading
import sys
import platform
import time
import pyperclip
import signal
import base64
import os
import struct
from pathlib import Path
from queue import Queue, Empty
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Default configuration
DEFAULT_PORT = 5000
BUFFER_SIZE = 10 * 1024 * 1024
CLIPBOARD_CHECK_INTERVAL = 1  # seconds
POLLING_INTERVAL = 5         # seconds
HEADER_SIZE = 4              # 4 bytes for message length

class ClipboardSharer:
    def __init__(self, host_ip, connect_to, port, nickname, watch_dir=None, gui_update_queue=None, clipboard_set_queue=None):
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
        self.gui_update_queue = gui_update_queue
        self.clipboard_set_queue = clipboard_set_queue

        self.start_server()
        self.connect_to_specified_hosts()
        if self.watch_dir and sys.platform == "darwin":
            self.monitor_directory(self.watch_dir)
        self.poll_for_updates()

    def recvall(self, sock, n):
        data = bytearray()
        while len(data) < n and not self.stop_event.is_set():
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def handle_client(self, client_socket, client_address):
        try:
            while not self.stop_event.is_set():
                # Peek at the first 4 bytes to see if this is a PULL request
                peek = client_socket.recv(4, socket.MSG_PEEK)
                if peek == b'PULL':
                    # Consume the PULL request
                    client_socket.recv(4)
                    # Respond with clipboard
                    self._gui_log(f"Received PULL request from {client_address}")
                    self._send_clipboard_to_client(client_socket)
                    break
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
                    self._gui_log(f"Decoding error from {client_address}: {ude}")
                    continue

                if received_content.startswith("FILE:"):
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
                        self._gui_log(f"Received file: {filename}")
                    except Exception as e:
                        self._gui_log(f"Error processing file transfer from {client_address}: {e}")
                    continue
                elif received_content.startswith("TEXT:"):
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
                    try:
                        source, clipboard_content = received_content.split(":", 1)
                    except ValueError:
                        source = client_address[0]
                        clipboard_content = received_content

                if clipboard_content != self.shared_clipboard:
                    # Always queue clipboard set for main thread
                    if self.clipboard_set_queue:
                        self.clipboard_set_queue.put(clipboard_content)
                    self.shared_clipboard = clipboard_content
                    self._gui_log(f"Clipboard updated from source: {source}")
                else:
                    self._gui_log(f"Clipboard content from source '{source}' is same as current clipboard. No update performed.")
        except Exception as e:
            self._gui_log(f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()
            if (client_address, client_socket) in self.connected_clients:
                self.connected_clients.remove((client_address, client_socket))
            self._gui_log(f"Connection closed with {client_address}")

    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.local_ip, self.port))
            self.server_socket.listen(5)
            self._gui_log(f"Server listening on {self.local_ip}:{self.port}")
            threading.Thread(target=self.accept_connections, daemon=True).start()
        except Exception as e:
            self._gui_log(f"Error starting server: {e}")

    def accept_connections(self):
        while not self.stop_event.is_set():
            try:
                client_socket, client_address = self.server_socket.accept()
                self._gui_log(f"Accepted connection from {client_address}")
                self.connected_clients.append((client_address, client_socket))
                # Send current clipboard to just this client if not empty
                if self.shared_clipboard:
                    self._gui_log(f"Sending current clipboard to {client_address}")
                    self._send_clipboard_to_client(client_socket)
                threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True).start()
            except OSError as e:
                if e.errno == 9:
                    self._gui_log("Server socket closed, stopping accept loop.")
                    break
                else:
                    self._gui_log(f"Error accepting connections: {e}")

    def _send_clipboard_to_client(self, client_socket):
        if not self.shared_clipboard:
            return
        if os.path.isfile(self.shared_clipboard):
            try:
                with open(self.shared_clipboard, "rb") as f:
                    file_data = f.read()
                b64_data = base64.b64encode(file_data).decode('utf-8')
                payload = f"FILE:{os.path.basename(self.shared_clipboard)}:{b64_data}"
            except Exception as e:
                self._gui_log(f"Error reading file '{os.path.basename(self.shared_clipboard)}': {e}")
                return
        else:
            payload = f"TEXT:{self.nickname}:{self.shared_clipboard}"
        message_bytes = payload.encode('utf-8')
        header = struct.pack('!I', len(message_bytes))
        framed_message = header + message_bytes
        try:
            client_socket.sendall(framed_message)
        except Exception as e:
            self._gui_log(f"Error sending clipboard to new client: {e}")

    def connect_to_specified_hosts(self):
        for host in self.connect_to:
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((host, self.port))
                self.connected_clients.append(((host, self.port), client_socket))
                self._gui_log(f"Connected to {host}:{self.port}")
                threading.Thread(target=self.handle_client, args=(client_socket, (host, self.port)), daemon=True).start()
                # Force clipboard share on new connection if clipboard is not empty
                if self.shared_clipboard:
                    self._gui_log("Sharing clipboard with new client(s)...")
                    self.notify_clients()
            except Exception as e:
                self._gui_log(f"Error connecting to {host}:{self.port} - {e}")

    def monitor_clipboard(self):
        pass  # Disabled clipboard polling/event-based monitoring for hotkey mode

    def _start_polling_clipboard(self):
        pass  # Disabled clipboard polling for hotkey mode

    def monitor_directory(self, directory):
        def directory_check():
            previously_seen = set(os.listdir(directory))
            while not self.stop_event.is_set():
                try:
                    current_files = set(os.listdir(directory))
                    new_files = current_files - previously_seen
                    for filename in new_files:
                        full_path = os.path.join(directory, filename)
                        if os.path.isfile(full_path):
                            self.shared_clipboard = full_path
                            self._gui_log(f"Detected new file in monitored directory: {filename}")
                            self.notify_clients()
                    previously_seen = current_files
                except Exception as e:
                    self._gui_log(f"Error monitoring directory '{directory}': {e}")
                finally:
                    self.stop_event.wait(1)
        threading.Thread(target=directory_check, daemon=True).start()

    def notify_clients(self):
        if not self.shared_clipboard:
            self._gui_log("Clipboard is empty, nothing to share.")
            return
        if os.path.isfile(self.shared_clipboard):
            try:
                with open(self.shared_clipboard, "rb") as f:
                    file_data = f.read()
                b64_data = base64.b64encode(file_data).decode('utf-8')
                payload = f"FILE:{os.path.basename(self.shared_clipboard)}:{b64_data}"
                self._gui_log(f"Sending file: {os.path.basename(self.shared_clipboard)}")
            except Exception as e:
                self._gui_log(f"Error reading file '{os.path.basename(self.shared_clipboard)}': {e}")
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
                self._gui_log(f"Error notifying client: {e}")

    # Removed setup_hotkey: now handled by Tkinter binding in the main window

    def poll_for_updates(self):
        def update_check():
            while not self.stop_event.is_set():
                self.stop_event.wait(POLLING_INTERVAL)
        threading.Thread(target=update_check, daemon=True).start()

    def quit_application(self):
        self.stop_event.set()
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        for client_address, client_socket in self.connected_clients:
            try:
                client_socket.close()
            except Exception:
                pass
        self.connected_clients.clear()

    def get_connected_clients_info(self):
        clients_info = []
        for client_address, _ in self.connected_clients:
            client_nick = self.nickname if self.nickname else client_address[0]
            clients_info.append(client_nick)
        return ', '.join(clients_info)

    def _gui_log(self, msg):
        if self.gui_update_queue:
            self.gui_update_queue.put(('log', msg))


def get_default_interface_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

class ClipboardSharerApp(tk.Tk):
    def __init__(self, connect_to_init=None, force_pull_mode=False):
        super().__init__()
        self.title("Clipboard Sharer")
        self.geometry("600x400")
        self.protocol("WM_DELETE_WINDOW", self.on_quit)
        self.gui_update_queue = Queue()
        self.clipboard_set_queue = Queue()
        self.clipboard_sharer = None
        self.last_update_time = None
        self.last_update_source = None
        self._force_pull_mode = force_pull_mode
        self._last_clipboard_sent = None  # For pull client echo suppression
        self._build_ui()
        # Set connect_to field from command-line/init
        if connect_to_init:
            self.connect_var.set(", ".join(connect_to_init))
        self._poll_gui_queue()
        self._poll_clipboard_set_queue()
        self._poll_last_update_label()
        self.bind_all('<Control-Alt-c>', self._on_hotkey)
        if self._force_pull_mode:
            self._log("[PULL] Polling thread started (forced by --connect).")
            self._pull_poll_interval = 2  # seconds
            self._last_pulled_clipboard = None
            self._pull_poll_clipboard()
        elif not sys.platform.startswith('linux'):
            self._last_polled_clipboard = None
            self._poll_clipboard_auto()
        else:
            self._log("[SERVER] No polling thread started (server mode, no --connect).")

    def _build_ui(self):
        self.attributes('-topmost', True)
        self.normal_frame = ttk.Frame(self)
        self.normal_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        # Clip button at the top
        self.clip_btn = ttk.Button(self.normal_frame, text="Clip", command=self._on_clip_btn)
        self.clip_btn.grid(row=0, column=0, pady=(0, 10), sticky=tk.W)
        # Minimize button
        self.min_btn = ttk.Button(self.normal_frame, text="Minimize", command=self._minimize_ui)
        self.min_btn.grid(row=0, column=1, pady=(0, 10), sticky=tk.W)

        # Host IP
        ttk.Label(self.normal_frame, text="Host IP:").grid(row=1, column=0, sticky=tk.W)
        self.host_var = tk.StringVar(value=get_default_interface_ip())
        ttk.Entry(self.normal_frame, textvariable=self.host_var, width=20).grid(row=1, column=1, sticky=tk.W)

        # Port
        ttk.Label(self.normal_frame, text="Port:").grid(row=2, column=0, sticky=tk.W)
        self.port_var = tk.IntVar(value=DEFAULT_PORT)
        ttk.Entry(self.normal_frame, textvariable=self.port_var, width=8).grid(row=2, column=1, sticky=tk.W)

        # Nickname
        ttk.Label(self.normal_frame, text="Nickname:").grid(row=3, column=0, sticky=tk.W)
        self.nick_var = tk.StringVar(value=platform.node())
        ttk.Entry(self.normal_frame, textvariable=self.nick_var, width=20).grid(row=3, column=1, sticky=tk.W)

        # Connect to
        ttk.Label(self.normal_frame, text="Connect to (comma-separated):").grid(row=4, column=0, sticky=tk.W)
        self.connect_var = tk.StringVar()
        ttk.Entry(self.normal_frame, textvariable=self.connect_var, width=40).grid(row=4, column=1, sticky=tk.W)

        # Watch dir (optional)
        ttk.Label(self.normal_frame, text="Watch Dir (macOS):").grid(row=5, column=0, sticky=tk.W)
        self.watch_dir_var = tk.StringVar()
        ttk.Entry(self.normal_frame, textvariable=self.watch_dir_var, width=40).grid(row=5, column=1, sticky=tk.W)
        ttk.Button(self.normal_frame, text="Browse", command=self._browse_dir).grid(row=5, column=2, sticky=tk.W)

        # Quit button
        self.quit_btn = ttk.Button(self.normal_frame, text="Quit", command=self.on_quit)
        self.quit_btn.grid(row=6, column=0, pady=10)

        # Connected clients
        ttk.Label(self.normal_frame, text="Connected Clients:").grid(row=7, column=0, sticky=tk.W)
        self.clients_var = tk.StringVar()
        ttk.Label(self.normal_frame, textvariable=self.clients_var).grid(row=7, column=1, sticky=tk.W)

        # Log area
        self.log_text = tk.Text(self.normal_frame, height=10, width=70, state=tk.DISABLED)
        self.log_text.grid(row=8, column=0, columnspan=3, pady=10)

        # Minimized window (Toplevel, created on demand)
        self.minimized_window = None

    def _browse_dir(self):
        dirname = filedialog.askdirectory()
        if dirname:
            self.watch_dir_var.set(dirname)

    # Removed start_sharing and stop_sharing: sharing is always enabled

    def on_quit(self):
        if self.clipboard_sharer:
            self.clipboard_sharer.quit_application()
            self.clipboard_sharer = None
        self.destroy()

    def _log(self, msg):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg + '\n')
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _poll_gui_queue(self):
        try:
            while True:
                msg_type, msg = self.gui_update_queue.get_nowait()
                if msg_type == 'log':
                    self._log(msg)
                elif msg_type == 'text':
                    self._log(msg)
        except Empty:
            pass
        if self.clipboard_sharer:
            self.clients_var.set(self.clipboard_sharer.get_connected_clients_info())
        self.after(200, self._poll_gui_queue)

    def _on_clip_btn(self, auto=False):
        if self.clipboard_sharer:
            try:
                content = pyperclip.paste()
                if content:
                    if content != self.clipboard_sharer.shared_clipboard:
                        self.clipboard_sharer.shared_clipboard = content
                        if auto:
                            self._log("Clipboard changed: sharing clipboard content.")
                        else:
                            self._log("Clip button pressed: sharing clipboard content.")
                        self.clipboard_sharer.notify_clients()
                        self.last_update_time = time.time()
                        self.last_update_source = "local"
                        # For pull client: track last sent clipboard
                        if self._force_pull_mode:
                            self._last_clipboard_sent = content
                else:
                    if not auto:
                        self._log("Clipboard is empty.")
            except Exception as e:
                if not auto:
                    self._log(f"Error reading clipboard: {e}")
        else:
            if not auto:
                self._log("Clipboard sharing is not started.")

    def _pull_poll_clipboard(self):
        # Only use the connect_to field at startup (do not monitor for changes)
        connect_to = [h.strip() for h in self.connect_var.get().split(',') if h.strip()]
        if connect_to:
            host = connect_to[0]
            port = self.clipboard_sharer.port if self.clipboard_sharer else DEFAULT_PORT
            try:
                self._log(f"[PULL] Connecting to {host}:{port} to request clipboard...")
                with socket.create_connection((host, port), timeout=20) as s:
                    self._log(f"[PULL] Sent PULL request to {host}:{port}")
                    s.sendall(b'PULL')
                    # Expect a clipboard message as in _send_clipboard_to_client
                    header = s.recv(4)
                    if not header:
                        raise Exception("No clipboard header received from server")
                    msg_length = struct.unpack('!I', header)[0]
                    message_bytes = b''
                    while len(message_bytes) < msg_length:
                        chunk = s.recv(msg_length - len(message_bytes))
                        if not chunk:
                            break
                        message_bytes += chunk
                    if not message_bytes:
                        raise Exception("No clipboard data received from server")
                    received_content = message_bytes.decode('utf-8')
                    # Only update if changed and not echo of last sent
                    if received_content != getattr(self, '_last_pulled_clipboard', None) and received_content != self._last_clipboard_sent:
                        self._log(f"[PULL] Clipboard changed, updating local clipboard.")
                        self._last_pulled_clipboard = received_content
                        # Parse and update clipboard
                        if received_content.startswith("FILE:"):
                            # Not supported in pull mode for now
                            self._log("[PULL] Received file in pull mode (not supported)")
                        elif received_content.startswith("TEXT:"):
                            parts = received_content.split(":", 2)
                            if len(parts) == 3:
                                clipboard_content = parts[2]
                                self.clipboard_clear()
                                self.clipboard_append(clipboard_content)
                                self._log("[PULL] Clipboard updated from remote (pull)")
                                self.last_update_time = time.time()
                                self.last_update_source = "remote"
                    else:
                        self._log(f"[PULL] Clipboard unchanged or echo of last sent.")
            except Exception as e:
                self._log(f"[PULL] Polling failed: {e}")
        else:
            self._log("[PULL] No server address set in 'Connect to' field.")
        self.after(getattr(self, '_pull_poll_interval', 2) * 1000, self._pull_poll_clipboard)

    def _poll_clipboard_auto(self):
        try:
            content = pyperclip.paste()
            if getattr(self, '_ignore_next_clipboard_poll', False):
                self._ignore_next_clipboard_poll = False
                self._last_polled_clipboard = content
            elif content != getattr(self, '_last_polled_clipboard', None):
                self._last_polled_clipboard = content
                self._on_clip_btn(auto=True)
        except Exception:
            pass
        self.after(1000, self._poll_clipboard_auto)

    def _poll_clipboard_set_queue(self):
        try:
            while True:
                content = self.clipboard_set_queue.get_nowait()
                self.clipboard_clear()
                self.clipboard_append(content)
                self._ignore_next_clipboard_poll = True
                self._log("Clipboard updated from remote.")
                self.last_update_time = time.time()
                self.last_update_source = "remote"
        except Empty:
            pass
        self.after(200, self._poll_clipboard_set_queue)

    def _poll_last_update_label(self):
        if hasattr(self, 'minimized_window') and self.minimized_window is not None and hasattr(self, 'min_last_update_label'):
            if self.last_update_time:
                elapsed = int(time.time() - self.last_update_time)
                src = self.last_update_source or "unknown"
                self.min_last_update_label.config(text=f"{elapsed}s ago from {src}")
            else:
                self.min_last_update_label.config(text="never")
        self.after(1000, self._poll_last_update_label)

    def _minimize_ui(self):
        # Hide main window
        self.withdraw()
        # Create minimized window if not already
        if not hasattr(self, 'minimized_window') or self.minimized_window is None:
            self.minimized_window = tk.Toplevel()
            self.minimized_window.geometry("220x80")
            self.minimized_window.overrideredirect(True)
            self.minimized_window.attributes('-topmost', True)
            # Clip button
            min_clip_btn = ttk.Button(self.minimized_window, text="Clip", command=self._on_clip_btn)
            min_clip_btn.grid(row=0, column=0, padx=5, pady=5)
            # Restore button
            restore_btn = ttk.Button(self.minimized_window, text="Restore", command=self._restore_ui)
            restore_btn.grid(row=0, column=1, padx=5, pady=5)
            # Last updated label
            import tkinter.font as tkfont
            small_font = tkfont.Font(size=8)
            self.min_last_update_label = ttk.Label(self.minimized_window, text="never", font=small_font)
            self.min_last_update_label.grid(row=1, column=0, columnspan=2, pady=(2, 0))
            self.minimized_window.protocol("WM_DELETE_WINDOW", self.on_quit)
            # Add drag support
            self._add_drag_support(self.minimized_window)
        else:
            self.minimized_window.deiconify()

    def _add_drag_support(self, window):
        def start_move(event):
            window._drag_start_x = event.x
            window._drag_start_y = event.y
        def do_move(event):
            x = window.winfo_x() + event.x - window._drag_start_x
            y = window.winfo_y() + event.y - window._drag_start_y
            window.geometry(f"+{x}+{y}")
        window.bind('<Button-1>', start_move)
        window.bind('<B1-Motion>', do_move)
        # Also bind to all children (buttons)
        for child in window.winfo_children():
            child.bind('<Button-1>', start_move)
            child.bind('<B1-Motion>', do_move)

    def _restore_ui(self):
        if hasattr(self, 'minimized_window') and self.minimized_window is not None:
            self.minimized_window.destroy()
            self.minimized_window = None
        self.deiconify()
        self.normal_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.geometry("600x400")
        self.overrideredirect(False)

    def _on_hotkey(self, event=None):
        self._on_clip_btn(auto=False)

if __name__ == "__main__":
    # Parse command-line args for connect_to
    import argparse
    parser = argparse.ArgumentParser(description="Clipboard Sharer")
    parser.add_argument("--host", help="This machine's IP address. If omitted, it will be auto-detected.")
    parser.add_argument("--connect", nargs="+", default=[], help="List of hostnames or IP addresses to connect to.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port for communication.")
    parser.add_argument("--nick", help="Nickname for this host.")
    parser.add_argument("--watch-dir", help="Directory to monitor for new files (macOS only).")
    args = parser.parse_args()


    force_pull_mode = bool(args.connect)
    app = ClipboardSharerApp(connect_to_init=args.connect, force_pull_mode=force_pull_mode)
    # Automatically start sharing on launch
    host = app.host_var.get() or args.host or get_default_interface_ip()
    port = app.port_var.get() or args.port
    nick = app.nick_var.get() or args.nick or platform.node()
    connect_to = [h.strip() for h in app.connect_var.get().split(',') if h.strip()] or args.connect
    watch_dir = app.watch_dir_var.get() or args.watch_dir
    app.clipboard_sharer = ClipboardSharer(host, connect_to, port, nick, watch_dir, gui_update_queue=app.gui_update_queue, clipboard_set_queue=app.clipboard_set_queue)
    app._log("Clipboard sharing started.")
    app.mainloop()
