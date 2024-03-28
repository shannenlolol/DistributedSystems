import threading
import tkinter as tk
from tkinter import ttk, messagebox
import socket
import struct
import os
import netifaces as ni
import subprocess

class ClientGUI:
    def __init__(self, master):
        
        self.master = master
        master.title("UDP Client for File Access")
        print(self.get_local_network())            


        # Server address and port
        self.server_address = ('localhost', 2222)

        # Initialize the client socket here
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.client_socket.settimeout(5)  # Optional: Set a timeout for socket operations

        # Response Display
        self.response_text = tk.Text(master, height=10, width=60)
        self.response_text.grid(row=0, column=0, padx=10, pady=5)
        self.response_text.config(state=tk.DISABLED)
              
        # GUI for selecting server IP
        self.frame_server_select = ttk.LabelFrame(master, text="Select Server IP")
        self.frame_server_select.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

        ttk.Button(self.frame_server_select, text="Scan Network", command=self.scan_network).grid(row=0, column=0, padx=5, pady=5)
        
        self.server_ip_var = tk.StringVar()
        self.combobox_server_ip = ttk.Combobox(self.frame_server_select, textvariable=self.server_ip_var, state="readonly")
        self.combobox_server_ip.grid(row=0, column=1, padx=5, pady=5)
        

        # Frame for Read File Operation
        self.frame_read = ttk.LabelFrame(master, text="Read File")
        self.frame_read.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        
        # Filepath Entry
        ttk.Label(self.frame_read, text="File Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.filepath = tk.StringVar()
        ttk.Entry(self.frame_read, textvariable=self.filepath, width=50).grid(row=0, column=1, padx=5, pady=5)
        
        # Offset Entry
        ttk.Label(self.frame_read, text="Offset:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.offset = tk.StringVar()
        ttk.Entry(self.frame_read, textvariable=self.offset).grid(row=1, column=1, padx=5, pady=5)
        
        # Length Entry
        ttk.Label(self.frame_read, text="Length:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.length = tk.StringVar()
        ttk.Entry(self.frame_read, textvariable=self.length).grid(row=2, column=1, padx=5, pady=5)
        
        # Read Button
        ttk.Button(self.frame_read, text="Read", command=self.read_file).grid(row=3, column=0, columnspan=2, pady=5)
        

        # Inside the ClientGUI __init__ method, add a frame for Insert File Operation
        self.frame_insert = ttk.LabelFrame(master, text="Insert Content")
        self.frame_insert.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

        # Filepath Entry
        ttk.Label(self.frame_insert, text="File Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.insert_filepath = tk.StringVar()
        ttk.Entry(self.frame_insert, textvariable=self.insert_filepath, width=50).grid(row=0, column=1, padx=5, pady=5)

        # Offset Entry
        ttk.Label(self.frame_insert, text="Offset:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.insert_offset = tk.StringVar()
        ttk.Entry(self.frame_insert, textvariable=self.insert_offset).grid(row=1, column=1, padx=5, pady=5)

        # Content Entry
        ttk.Label(self.frame_insert, text="Content:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.insert_content = tk.StringVar()
        ttk.Entry(self.frame_insert, textvariable=self.insert_content).grid(row=2, column=1, padx=5, pady=5)

        # Insert Button
        ttk.Button(self.frame_insert, text="Insert", command=self.insert_content_to_file).grid(row=3, column=0, columnspan=2, pady=5)

        # Monitoring File Operation
        self.frame_monitor = ttk.LabelFrame(master, text="Monitor File")
        self.frame_monitor.grid(row=4, column=0, padx=10, pady=10, sticky="ew")

        # Filepath Entry for Monitoring
        ttk.Label(self.frame_monitor, text="File Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.monitor_filepath = tk.StringVar()
        ttk.Entry(self.frame_monitor, textvariable=self.monitor_filepath, width=50).grid(row=0, column=1, padx=5, pady=5)

        # Interval Entry
        ttk.Label(self.frame_monitor, text="Interval (seconds):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.monitor_interval = tk.StringVar()
        ttk.Entry(self.frame_monitor, textvariable=self.monitor_interval).grid(row=1, column=1, padx=5, pady=5)

        # Monitor Button
        ttk.Button(self.frame_monitor, text="Start Monitoring", command=self.start_monitoring).grid(row=2, column=0, columnspan=2, pady=5)

    def read_file(self):
        filepath = self.filepath.get()
        offset = int(self.offset.get())
        length = int(self.length.get())
        response = self.send_read_request(filepath, offset, length)
        success, content = self.unpack_response(response)
        if success:
            message = content.decode('utf-8')
        else:
            message = "Error: " + content.decode('utf-8')
        self.display_response(message)
        
    def send_read_request(self, filepath, offset, length):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
            filepath_bytes = filepath.encode('utf-8')
            message = struct.pack(f'!II{len(filepath_bytes)}sII', 1, len(filepath_bytes), filepath_bytes, offset, length)
            client_socket.sendto(message, self.server_address)
            response, _ = client_socket.recvfrom(4096)
            return response
        
    def unpack_response(self, data):
        success, content_length = struct.unpack('!?I', data[:5])
        content = data[5:5+content_length]
        return success, content
    
    def display_response(self, message):
        self.response_text.config(state=tk.NORMAL)
        self.response_text.delete(1.0, tk.END)
        self.response_text.insert(tk.END, message)
        self.response_text.config(state=tk.DISABLED)

    def insert_content_to_file(self):
        filepath = self.insert_filepath.get()
        offset = int(self.insert_offset.get())
        content = self.insert_content.get().encode('utf-8')
        response = self.send_insert_request(filepath, offset, content)
        success, message = self.unpack_response(response)
        if success:
            message = "Insertion successful"
        else:
            message = "Error: " + message.decode('utf-8')
        self.display_response(message)

    def send_insert_request(self, filepath, offset, content):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
            filepath_bytes = filepath.encode('utf-8')
            message = struct.pack(f'!II{len(filepath_bytes)}sII{len(content)}s', 2, len(filepath_bytes), filepath_bytes, offset, len(content), content)
            client_socket.sendto(message, self.server_address)
            response, _ = client_socket.recvfrom(4096)
            return response

    def start_monitoring(self):
        filepath = self.monitor_filepath.get()
        interval = int(self.monitor_interval.get())
        self.send_monitor_request(filepath, interval)
        # Listen for updates in a separate thread to avoid blocking the UI
        self.monitor_thread = threading.Thread(target=self.listen_for_updates, daemon=True)
        self.monitor_thread.start()

    def send_monitor_request(self, filepath, interval):
        filepath_bytes = filepath.encode('utf-8')
        message = struct.pack('!II{}sI'.format(len(filepath_bytes)), 3, len(filepath_bytes), filepath_bytes, interval)
        self.client_socket.sendto(message, self.server_address)

    def listen_for_updates(self):
        while True:
            try:
                response, _ = self.client_socket.recvfrom(4096)
                # Assuming all monitoring updates are plain text and do not require unpacking with unpack_response
                message = response.decode('utf-8')
                print(f"Received message: {message}")  # For debugging
                self.display_response(f"Monitoring Update: {message}")
            except Exception as e:
                print(f"Stopped listening for monitoring updates: {e}")
                break

    def display_response(self, message):
        if self.response_text.winfo_exists():  # Check if the widget still exists
            self.response_text.config(state=tk.NORMAL)
            self.response_text.insert(tk.END, message + "\n")
            self.response_text.see(tk.END)  # Scroll to the end
            self.response_text.config(state=tk.DISABLED)

    def scan_network(self):
            """Scans the local network for active devices."""
            # Assuming your network is 192.168.1.x
            subnet = "192.168.18"
            active_ips = []
            for i in range(1, 10):
                ip = f"{subnet}.{i}"
                print(ip)
                result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL)
                if result.returncode == 0:
                    print(ip, "DETECTED")
                    active_ips.append(ip)
            self.combobox_server_ip['values'] = active_ips
            if active_ips:
                self.combobox_server_ip.current(0)

    def get_local_network(self):
        # Get the default gateway interface
        gws = ni.gateways()
        default_gateway = gws['default'][ni.AF_INET][1]

        # Get the IP address of the default gateway interface
        ip = ni.ifaddresses(default_gateway)[ni.AF_INET][0]['addr']
        netmask = ni.ifaddresses(default_gateway)[ni.AF_INET][0]['netmask']

        # Calculate the network
        ip_parts = ip.split('.')
        netmask_parts = netmask.split('.')
        network_parts = [str(int(ip_parts[i]) & int(netmask_parts[i])) for i in range(4)]
        network = '.'.join(network_parts)
        return network

    


def main():
    root = tk.Tk()
    gui = ClientGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()