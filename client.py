import os
import random
import socket
import struct
import subprocess
import threading
import time
import tkinter as tk
import uuid
from tkinter import messagebox, ttk

import netifaces as ni


class ClientGUI:
    def __init__(self, master, freshness_interval=30): 
        self.master = master
        self.freshness_interval = freshness_interval
        master.title("UDP Client for File Access")

        self.cache = {}  # Initialize an empty cache

        # to retransmit "dropped" messages in simulation, if not can comment out
        self.pending_requests = {}  # request_id -> {"send_time": timestamp, "data": request_data}
        self.check_pending_requests_thread = threading.Thread(target=self.check_pending_requests, daemon=True)
        self.check_pending_requests_thread.start()
        
        print(self.get_local_network())            

        # Server address and port
        self.server_address = ('localhost', 2222)

        # Initialize the client socket here
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

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

        # GUI for Delete File Operation
        self.frame_delete = ttk.LabelFrame(master, text="Delete File")
        self.frame_delete.grid(row=5, column=0, padx=10, pady=10, sticky="ew")

        # Filepath Entry for Delete
        ttk.Label(self.frame_delete, text="File Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.delete_filepath = tk.StringVar()
        ttk.Entry(self.frame_delete, textvariable=self.delete_filepath, width=50).grid(row=0, column=1, padx=5, pady=5)

        # Delete Button
        ttk.Button(self.frame_delete, text="Delete", command=self.delete_file).grid(row=1, column=0, columnspan=2, pady=5)

        # GUI for Create File Operation
        self.frame_create = ttk.LabelFrame(master, text="Create File")
        self.frame_create.grid(row=6, column=0, padx=10, pady=10, sticky="ew")

        # Filepath Entry for Create
        ttk.Label(self.frame_create, text="File Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.create_filepath = tk.StringVar()
        ttk.Entry(self.frame_create, textvariable=self.create_filepath, width=50).grid(row=0, column=1, padx=5, pady=5)

        # Create Button
        ttk.Button(self.frame_create, text="Create", command=self.create_file).grid(row=1, column=0, columnspan=2, pady=5)
    
    def read_file(self):
        filepath = self.filepath.get()
        offset = int(self.offset.get())
        length = int(self.length.get())

        # Generate a unique key for each file read request based on filepath, offset, and length
        cache_key = (filepath, offset, length)
        
        # Check if the request is cached and the cached data is still fresh
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if (time.time() - timestamp) < self.freshness_interval:
                # Use cached data
                print(f"Reading {cache_key} request from cache")
                self.display_response(cached_data.decode('utf-8'))
                return
        
        # If data is not in cache or is stale, fetch from server
        response = self.send_read_request(filepath, offset, length)
        success, content = self.unpack_response(response)
        if success:
            # Update cache with new data
            self.cache[cache_key] = (content, time.time())
            message = content.decode('utf-8')
        else:
            message = "Error: " + content.decode('utf-8')
        self.display_response(message)
                
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
        # Invalidate relevant cache entries
        self.invalidate_cache(filepath)
        response = self.send_insert_request(filepath, offset, content)
        success, message = self.unpack_response(response)
        if success:
            message = "Insertion successful"
        else:
            message = "Error: " + message.decode('utf-8')
        self.display_response(message)


    def start_monitoring(self):
        filepath = self.monitor_filepath.get()
        interval = int(self.monitor_interval.get())
        response = self.send_monitor_request(filepath, interval)
        success, message = self.unpack_response(response)
        if success:
            # Listen for updates in a separate thread to avoid blocking the UI
            self.monitor_thread = threading.Thread(target=self.listen_for_updates, daemon=True)
            self.monitor_thread.start()
            message = message.decode('utf-8')
        else:
            message = "Monitoring Error " + message.decode('utf-8')
        self.display_response(message)

    def listen_for_updates(self):
        while True:
            try:
                response, _ = self.client_socket.recvfrom(4096)
                # Assuming all monitoring updates are plain text and do not require unpacking with unpack_response
                message = response.decode('utf-8')
                print(f"Received message: {message}")  # For debugging

                # Getting file path from message
                filepath = message.split(' updated: ')[0]

                # Invalidate cache entries related to the updated file
                self.invalidate_cache(filepath)

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
    
    def delete_file(self):
        filepath = self.delete_filepath.get()
        response = self.send_delete_request(filepath)
        success, message = self.unpack_response(response)
        if success:
            message = "Deletion successful"
        else:
            message = "Error: " + message.decode('utf-8')
        self.display_response(message)

                
    def create_file(self):
        filepath = self.create_filepath.get()
        response = self.send_create_request(filepath)
        success, message = self.unpack_response(response)
        if success:
            message = "Creation successful"
        else:
            message = "Error: " + message.decode('utf-8')
        self.display_response(message)
    
    def generate_request_id(self):
        """Generate a unique request ID."""
        return uuid.uuid4().hex
    
    def send_generic_request(self, service_id, filepath, *additional_data):

        drop_rate = 0.3  # 30% chance to simulate a message drop
        if random.random() < drop_rate:
            print(f"Simulating drop of request to {filepath}")
            return  # Simulate drop by returning early

        request_id = self.generate_request_id().encode('utf-8')
        filepath_bytes = filepath.encode('utf-8')

        # Prepare the beginning part of the message with service_id, request_id, and filepath
        # Note: No need to include the length of request_id and filepath_bytes in the format string,
        # as we're directly specifying these in the pack arguments
        message_parts = [
            struct.pack('!I', len(request_id)),  # Length of request_id
            request_id,  # request_id itself
            struct.pack('!I', service_id),  # Service ID
            struct.pack('!I', len(filepath_bytes)),  # Length of filepath
            filepath_bytes  # filepath itself
        ]
        
        # Append additional data directly to message_parts
        for data in additional_data:
            if isinstance(data, bytes):
                message_parts.append(data)
            else:
                # This ensures that all additional data must be bytes; otherwise, raise an error
                raise ValueError("additional_data elements must be bytes objects")

        # Combine all parts of the message
        message = b''.join(message_parts)

        # Tracking request for simulation
        self.pending_requests[request_id] = {"send_time": time.time(), "data": message}
        
        self.client_socket.sendto(message, self.server_address)
        response, _ = self.client_socket.recvfrom(4096)
        # Upon receiving a response, remove the request from pending_requests
        del self.pending_requests[request_id]
        return response


    def send_read_request(self, filepath, offset, length):
      # Pack offset and length as additional data
        offset_bytes = struct.pack('!I', offset)
        length_bytes = struct.pack('!I', length)
        return self.send_generic_request(1, filepath, offset_bytes, length_bytes)

    def send_insert_request(self, filepath, offset, content):
        """
        Sends an insert request to the server with the specified filepath, offset, and content.
        Both offset (as bytes) and content (already in bytes) are passed as additional data.
        """
        offset_bytes = struct.pack('!I', offset)
        # Now 'content' and 'offset' are sent as separate parameters
        return self.send_generic_request(2, filepath, offset_bytes, content)
        
    def send_monitor_request(self, filepath, interval):
        """
        Sends a monitor request to the server with the specified filepath and interval.
        """
        # Interval needs to be packed as bytes since it's a numerical value
        interval_bytes = struct.pack('!I', interval)
        return self.send_generic_request(3, filepath, interval_bytes)

    def send_delete_request(self, filepath):
        """
        Sends a delete request to the server for the specified filepath.
        """
        # No additional data beyond the filepath is needed for delete, hence no extra parameters beyond the service ID and filepath
        return self.send_generic_request(4, filepath)
        
    def send_create_request(self, filepath):
        """
        Sends a create request to the server for the specified filepath.
        """
        # Similar to delete, creating a file requires only the filepath
        return self.send_generic_request(5, filepath)
       
    def invalidate_cache(self, filepath):
        # Invalidate all cache entries related to the filepath
        for key in list(self.cache.keys()):
            if key[0] == filepath:
                print(f"Invalidating cache of key: {key}")
                del self.cache[key]

    def check_pending_requests(self):
        """Periodically checks for pending requests that need to be resent."""
        while True:
            current_time = time.time()
            for request_id, request_details in list(self.pending_requests.items()):
                if current_time - request_details["send_time"] > 60:  # 60-second timeout
                    print(f"Resending request {request_id} due to timeout")
                    # Resend the request
                    self.client_socket.sendto(request_details["data"], self.server_address)
                    # Update the send time
                    request_details["send_time"] = current_time
            time.sleep(15)  # Check every 15 seconds
        

def main(freshness_interval=60):
    root = tk.Tk()
    gui = ClientGUI(root, freshness_interval=freshness_interval)
    root.mainloop()

if __name__ == "__main__":
    main()