
import http.server
import ssl
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import socket
import webbrowser
from datetime import datetime
from functools import partial
from collections import deque
import logging
import time
import subprocess
import platform
import tempfile

# Global bandwidth tracker
bandwidth_used = 0
request_count = 0
log_records = deque(maxlen=1000)
start_time = time.time()
max_request_size = 0

LOG_FILE = "server.log"
APP_DIR = os.path.dirname(os.path.abspath(__file__))

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, directory=None, **kwargs):
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format, *args):
        global bandwidth_used, request_count, max_request_size
        message = format % args
        request_time = datetime.now().strftime('%H:%M:%S')
        ip = self.client_address[0]
        method = self.command
        path = self.path
        size = self.headers.get('Content-Length') or 0
        try:
            size = int(size)
        except ValueError:
            size = 0

        bandwidth_used += size
        max_request_size = max(max_request_size, size)
        request_count += 1

        log_records.append((request_time, ip, method, path, size))
        logging.info(f"{ip} {method} {path} {size}B")

        if app:
            app.update_log_table()
            app.update_dashboard()

    def do_GET(self):
        self.log_request("GET")
        super().do_GET()

    def do_POST(self):
        self.log_request("POST")
        super().do_POST()

    def log_request(self, method):
        self.log_message("%s request for %s", method, self.path)


class ThreadingHTTPSServer(http.server.ThreadingHTTPServer):
    daemon_threads = True


class HTTPSServer:
    def __init__(self, port, directory, cert=None, key=None, use_https=True):
        self.server_address = ('', port)
        self.directory = directory
        self.cert = cert
        self.key = key
        self.use_https = use_https
        self.httpd = ThreadingHTTPSServer(self.server_address, self.create_handler())
        self.is_running = False

    def create_handler(self):
        return lambda *args, **kwargs: CustomHTTPRequestHandler(*args, directory=self.directory, **kwargs)

    def start(self):
        if not self.is_running:
            if self.use_https:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certfile=self.cert, keyfile=self.key)
                self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
            self.is_running = True
            try:
                self.httpd.serve_forever()
            except Exception as e:
                print(f"Server stopped with error: {e}")

    def stop(self):
        if self.is_running:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.is_running = False


class App:
    def __init__(self, root):
        self.root = root
        self.server = None
        self.port = tk.IntVar(value=12345)
        self.cert_path = tk.StringVar()
        self.key_path = tk.StringVar()
        self.dir_path = tk.StringVar()
        self.search_method = tk.StringVar()
        self.search_ip = tk.StringVar()
        self.use_https = tk.BooleanVar(value=True)

        self.root.title("HTTPS Server Dashboard")
        self.root.geometry("1100x650")
        self.root.protocol("WM_DELETE_WINDOW", self.exit_app)

        self.setup_styles()
        self.build_menu()
        self.build_ui()
        self.autodetect_certificates()
        self.update_dashboard()
        self.poll_dashboard()

    def setup_styles(self):
        self.style = ttk.Style()
        bg = "#f0f0f0"
        fg = "#000000"
        self.root.configure(bg=bg)
        self.style.configure("TLabel", background=bg, foreground=fg)
        self.style.configure("TButton", padding=5)
        self.style.configure("TEntry", padding=3)
        self.style.configure("Treeview", background="#ffffff", foreground=fg, fieldbackground="#ffffff")

    def build_menu(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Generate Certificate", command=self.generate_certificate_window)
        menubar.add_cascade(label="File", menu=file_menu)
        self.root.config(menu=menubar)

    def build_ui(self):
        self.main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        self.main_pane.pack(fill=tk.BOTH, expand=True)

        self.left_panel = tk.Frame(self.main_pane)
        self.main_pane.add(self.left_panel, width=380)

        self.right_panel = tk.Frame(self.main_pane)
        self.main_pane.add(self.right_panel)

        ttk.Label(self.left_panel, text="Port:").pack(anchor="w")
        ttk.Entry(self.left_panel, textvariable=self.port).pack(fill=tk.X)

        self.make_file_input("Certificate File:", self.cert_path, self.browse_cert)
        self.make_file_input("Key File:", self.key_path, self.browse_key)
        self.make_file_input("Directory:", self.dir_path, self.browse_dir)

        ttk.Checkbutton(self.left_panel, text="Use HTTPS", variable=self.use_https).pack(anchor="w", pady=4)

        ttk.Button(self.left_panel, text="Start Server", command=self.toggle_server).pack(fill=tk.X, pady=2)
        ttk.Button(self.left_panel, text="Open in Browser", command=self.open_in_browser).pack(fill=tk.X, pady=2)

        self.dashboard = ttk.LabelFrame(self.left_panel, text="Dashboard")
        self.dashboard.pack(fill=tk.BOTH, expand=True, padx=5, pady=10)

        self.status_lbl = ttk.Label(self.dashboard, text="Status: Stopped")
        self.status_lbl.pack(anchor="w")

        self.requests_lbl = ttk.Label(self.dashboard, text="Requests: 0")
        self.requests_lbl.pack(anchor="w")

        self.bandwidth_lbl = ttk.Label(self.dashboard, text="Bandwidth: 0 MB")
        self.bandwidth_lbl.pack(anchor="w")

        self.uptime_lbl = ttk.Label(self.dashboard, text="Uptime: 0s")
        self.uptime_lbl.pack(anchor="w")

        self.peak_lbl = ttk.Label(self.dashboard, text="Peak Req Size: 0 B")
        self.peak_lbl.pack(anchor="w")

        filter_frame = ttk.Frame(self.right_panel)
        filter_frame.pack(fill=tk.X)

        ttk.Label(filter_frame, text="Filter Method:").pack(side=tk.LEFT, padx=2)
        ttk.Entry(filter_frame, textvariable=self.search_method, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Label(filter_frame, text="Filter IP:").pack(side=tk.LEFT, padx=2)
        ttk.Entry(filter_frame, textvariable=self.search_ip, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(filter_frame, text="Apply", command=self.update_log_table).pack(side=tk.LEFT, padx=5)

        self.tree = ttk.Treeview(self.right_panel, columns=("time", "ip", "method", "path", "size"), show="headings")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, stretch=True)
        self.tree.pack(fill=tk.BOTH, expand=True)

    def make_file_input(self, label, var, command):
        frame = ttk.Frame(self.left_panel)
        frame.pack(fill=tk.X, pady=2)
        ttk.Label(frame, text=label).pack(anchor="w")
        row = ttk.Frame(frame)
        row.pack(fill=tk.X)
        ttk.Entry(row, textvariable=var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(row, text="Browse", command=command).pack(side=tk.RIGHT)

    def toggle_server(self):
        if not self.server or not self.server.is_running:
            if not self.dir_path.get() or (self.use_https.get() and (not self.cert_path.get() or not self.key_path.get())):
                messagebox.showerror("Error", "Required fields missing.")
                return
            self.server = HTTPSServer(
                port=self.port.get(),
                directory=self.dir_path.get(),
                cert=self.cert_path.get(),
                key=self.key_path.get(),
                use_https=self.use_https.get()
            )
            threading.Thread(target=self.server.start, daemon=True).start()
            self.status_lbl.config(text=f"Status: Running on port {self.port.get()}")
        else:
            self.server.stop()
            self.status_lbl.config(text="Status: Stopped")
        self.update_dashboard()

    def open_in_browser(self):
        proto = "https" if self.use_https.get() else "http"
        url = f"{proto}://localhost:{self.port.get()}/"
        webbrowser.open(url)

    def update_dashboard(self):
        global start_time
        self.requests_lbl.config(text=f"Requests: {request_count}")
        size_mb = bandwidth_used / (1024 * 1024)
        self.bandwidth_lbl.config(text=f"Bandwidth: {size_mb:.2f} MB")
        self.peak_lbl.config(text=f"Peak Req Size: {max_request_size} B")
        uptime = int(time.time() - start_time)
        self.uptime_lbl.config(text=f"Uptime: {uptime}s")

    def poll_dashboard(self):
        self.update_dashboard()
        self.root.after(1000, self.poll_dashboard)

    def update_log_table(self):
        method_filter = self.search_method.get().lower()
        ip_filter = self.search_ip.get()
        self.tree.delete(*self.tree.get_children())
        for row in log_records:
            if (method_filter and method_filter not in row[2].lower()) or (ip_filter and ip_filter not in row[1]):
                continue
            self.tree.insert("", "end", values=row)

    def browse_cert(self):
        path = filedialog.askopenfilename(title="Select Certificate File")
        if path:
            self.cert_path.set(path)

    def browse_key(self):
        path = filedialog.askopenfilename(title="Select Key File")
        if path:
            self.key_path.set(path)

    def browse_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.dir_path.set(path)

    def autodetect_certificates(self):
        for file in os.listdir(APP_DIR):
            if file.endswith(".pem") or file.endswith(".crt"):
                self.cert_path.set(os.path.join(APP_DIR, file))
            if file.endswith(".key"):
                self.key_path.set(os.path.join(APP_DIR, file))

    def generate_certificate_window(self):
        win = tk.Toplevel(self.root)
        win.title("Generate Self-Signed Certificate")
        win.geometry("300x300")

        fields = {
            "Country": tk.StringVar(),
            "State": tk.StringVar(),
            "Location": tk.StringVar(),
            "Organization": tk.StringVar(),
            "Common Name": tk.StringVar(),
        }

        for label, var in fields.items():
            ttk.Label(win, text=label).pack()
            ttk.Entry(win, textvariable=var).pack(fill=tk.X)

        def generate():
            subj = "/C={}/ST={}/L={}/O={}/CN={}".format(
                fields["Country"].get(),
                fields["State"].get(),
                fields["Location"].get(),
                fields["Organization"].get(),
                fields["Common Name"].get()
            )
            certfile = os.path.join(APP_DIR, "cert.pem")
            keyfile = os.path.join(APP_DIR, "key.key")
            cmd = [
                "openssl", "req", "-x509", "-nodes", "-days", "365",
                "-newkey", "rsa:2048",
                "-keyout", keyfile,
                "-out", certfile,
                "-subj", subj
            ]
            try:
                subprocess.check_call(cmd)
                messagebox.showinfo("Success", "Certificate generated.")
                self.cert_path.set(certfile)
                self.key_path.set(keyfile)
                win.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ttk.Button(win, text="Generate", command=generate).pack(pady=10)

    def exit_app(self):
        if self.server and self.server.is_running:
            self.server.stop()
        self.root.destroy()


if __name__ == "__main__":
    app = None
    root = tk.Tk()
    app = App(root)
    root.mainloop()
