import argparse
from datetime import datetime
import random
import socket
import struct
import threading
import time
import tkinter as tk
import uuid
from tkinter import ttk

SERVER_IP = '10.91.230.112'

class ClientGUI:
    def __init__(self, master, freshness_interval):
        self.master = master
        master.title("UDP Client for File Access")
        master.state('zoomed')

        self.cache = {}
        self.freshness_interval = freshness_interval

        self.pending_requests = {}
        self.check_pending_requests_thread = threading.Thread(target=self.check_pending_requests, daemon=True)
        self.check_pending_requests_thread.start()

        self.server_address = (SERVER_IP, 2222)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Set up the scrollable canvas
        self.canvas = tk.Canvas(master, highlightthickness=0)  
        self.scrollbar = tk.Scrollbar(master, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Use a Frame to contain all widgets, which will is inside the canvas
        self.scrollable_frame = ttk.Frame(self.canvas)
        self.canvas_frame = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="center")
        self.scrollable_frame.bind("<Configure>", self.onFrameConfigure)
        master.bind("<Configure>", self.onMasterConfigure)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Response log -----------------------------------------------------------------------------------------------------------
        self.response_text = tk.Text(self.scrollable_frame, height=10, width=80)
        self.response_text.grid(row=0, column=0, padx=10, pady=30)
        self.response_text.config(state=tk.DISABLED)

        # Frame for Server IP -----------------------------------------------------------------------------------------------------------
        self.frame_ip = ttk.LabelFrame(self.scrollable_frame, text="Set Server IP")
        self.frame_ip.grid(row=1, column=0, padx=10, pady=10)

        # Input field for Server IP
        ttk.Label(self.frame_ip, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
        self.server_ip_var = tk.StringVar(value=SERVER_IP)  # Default IP
        ttk.Entry(self.frame_ip, textvariable=self.server_ip_var, width=50).grid(row=0, column=1, padx=5, pady=5)

        # Input field for Server Port
        ttk.Label(self.frame_ip, text="Server Port:").grid(row=1, column=0, padx=5, pady=5)
        self.server_port_var = tk.StringVar(value='2222')  # Default port
        ttk.Entry(self.frame_ip, textvariable=self.server_port_var).grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Button to update server address
        ttk.Button(self.frame_ip, text="Update Server Address", command=self.update_server_address).grid(row=2, column=0, columnspan=2, pady=5)


        # Frame for Read File Operation -----------------------------------------------------------------------------------------------------------
        self.frame_read = ttk.LabelFrame(self.scrollable_frame, text="Read File")
        self.frame_read.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        
        # Filepath Entry
        ttk.Label(self.frame_read, text="File Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.filepath = tk.StringVar()
        ttk.Entry(self.frame_read, textvariable=self.filepath, width=50).grid(row=0, column=1, padx=5, pady=5)
        
        # Offset Entry
        ttk.Label(self.frame_read, text="Offset:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.offset = tk.StringVar()
        ttk.Entry(self.frame_read, textvariable=self.offset).grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        # Length Entry
        ttk.Label(self.frame_read, text="Length:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.length = tk.StringVar()
        ttk.Entry(self.frame_read, textvariable=self.length).grid(row=2, column=1, padx=5, pady=5 , sticky="w")
        
        # Read Button
        self.read_button = ttk.Button(self.frame_read, text="Read", command=self.read_file)
        self.read_button.grid(row=3, column=0, columnspan=2, pady=5)
        

        # Frame for Insert File Operation -----------------------------------------------------------------------------------------------------------
        self.frame_insert = ttk.LabelFrame(self.scrollable_frame, text="Insert Content")
        self.frame_insert.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

        # Filepath Entry
        ttk.Label(self.frame_insert, text="File Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.insert_filepath = tk.StringVar()
        ttk.Entry(self.frame_insert, textvariable=self.insert_filepath, width=50).grid(row=0, column=1, padx=5, pady=5)

        # Offset Entry
        ttk.Label(self.frame_insert, text="Offset:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.insert_offset = tk.StringVar()
        ttk.Entry(self.frame_insert, textvariable=self.insert_offset).grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Content Entry
        ttk.Label(self.frame_insert, text="Content:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.insert_content = tk.StringVar()
        ttk.Entry(self.frame_insert, textvariable=self.insert_content).grid(row=2, column=1, padx=5, pady=5, sticky="w")

        # Insert Button
        self.insert_button = ttk.Button(self.frame_insert, text="Insert", command=self.insert_content_to_file)
        self.insert_button.grid(row=3, column=0, columnspan=2, pady=5)

        # Frame for Monitoring File Operation -----------------------------------------------------------------------------------------------------------
        self.frame_monitor = ttk.LabelFrame(self.scrollable_frame, text="Monitor File")
        self.frame_monitor.grid(row=4, column=0, padx=10, pady=10, sticky="ew")

        # Filepath Entry for Monitoring
        ttk.Label(self.frame_monitor, text="File Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.monitor_filepath = tk.StringVar()
        ttk.Entry(self.frame_monitor, textvariable=self.monitor_filepath, width=50).grid(row=0, column=1, padx=5, pady=5)

        # Interval Entry
        ttk.Label(self.frame_monitor, text="Interval (s):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.monitor_interval = tk.StringVar()
        ttk.Entry(self.frame_monitor, textvariable=self.monitor_interval).grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Monitor Button
        self.monitor_button = ttk.Button(self.frame_monitor, text="Start Monitoring", command=self.start_monitoring)
        self.monitor_button.grid(row=2, column=0, columnspan=2, pady=5)

        # Frame for Delete File Operation -----------------------------------------------------------------------------------------------------------
        self.frame_delete = ttk.LabelFrame(self.scrollable_frame, text="Delete File")
        self.frame_delete.grid(row=5, column=0, padx=10, pady=10, sticky="ew")

        # Filepath Entry for Delete
        ttk.Label(self.frame_delete, text="File Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.delete_filepath = tk.StringVar()
        ttk.Entry(self.frame_delete, textvariable=self.delete_filepath, width=50).grid(row=0, column=1, padx=5, pady=5)

        # Delete Button
        self.delete_button = ttk.Button(self.frame_delete, text="Delete", command=self.delete_file)
        self.delete_button.grid(row=1, column=0, columnspan=2, pady=5)

        # Frame for Create File Operation -----------------------------------------------------------------------------------------------------------
        self.frame_create = ttk.LabelFrame(self.scrollable_frame, text="Create File")
        self.frame_create.grid(row=6, column=0, padx=10, pady=10, sticky="ew")

        # Filepath Entry for Create
        ttk.Label(self.frame_create, text="File Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.create_filepath = tk.StringVar()
        ttk.Entry(self.frame_create, textvariable=self.create_filepath, width=50).grid(row=0, column=1, padx=5, pady=5)

        # Create Button
        self.create_button = ttk.Button(self.frame_create, text="Create", command=self.create_file)
        self.create_button.grid(row=1, column=0, columnspan=2, pady=5)
    

    def update_server_address(self):
        """
        Update the server address using values from the input fields
        """
        ip = self.server_ip_var.get()
        port = int(self.server_port_var.get())
        self.server_address = (ip, port)
        print(f"Updated server address to: {self.server_address}")

    def onFrameConfigure(self, event=None):
        """
        Reset the scroll region to encompass the inner frame
        """
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.recenterCanvasWindow()

    def onMasterConfigure(self, event=None):
        """
        Center the canvas window when the main window is resized
        """
        canvas_width = self.canvas.winfo_width()
        canvas_height = self.canvas.winfo_height()
        frame_width = self.scrollable_frame.winfo_reqwidth()
        frame_height = self.scrollable_frame.winfo_reqheight()
        
        # Calculate the new position coordinates for the frame
        new_x_position = max((canvas_width - frame_width) // 2, 0)
        new_y_position = max((canvas_height - frame_height) // 2, 0)
        
        self.canvas.coords(self.canvas_frame, (new_x_position, new_y_position))

        # Set canvas window's width to frame's width and height to either frame's height or the height of the canvas
        if canvas_width > frame_width or canvas_height > frame_height:
            self.canvas.itemconfig(self.canvas_frame, width=frame_width, height=max(frame_height, canvas_height))


    def recenterCanvasWindow(self):
        """
        Re-centers the canvas window
        """
        self.master.update_idletasks() 
        canvas_width = self.canvas.winfo_width()
        frame_width = self.scrollable_frame.winfo_reqwidth()
        new_x_position = max((canvas_width - frame_width) // 2, 0)
        self.canvas.coords(self.canvas_frame, new_x_position, 0)

        # Adjust the width of the canvas window to match the frame's width if the canvas is larger
        if canvas_width > frame_width:
            self.canvas.itemconfig(self.canvas_frame, width=frame_width)
        else:
            self.canvas.itemconfig(self.canvas_frame, width=canvas_width)


    def display_response(self, message):
        """
        Displays a server response in the text widget, prepended with a timestamp.
        """
        timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        message_with_timestamp = f"{timestamp} - {message}"
        if self.response_text.winfo_exists():  
            self.response_text.config(state=tk.NORMAL)
            self.response_text.insert(tk.END, message_with_timestamp + "\n")
            self.response_text.see(tk.END) 
            self.response_text.config(state=tk.DISABLED)

    def unpack_response(self, data):
        """
        Extracts and returns the success status and content from a server response packet.
        """
        success, content_length = struct.unpack('!?I', data[:5])
        content = data[5:5+content_length]
        return success, content

    def generate_request_id(self):
        """
        Generate a unique identifier for each request sent to the server.
        """
        return uuid.uuid4().hex
    
    def invalidate_cache(self, filepath):
        """
        Invalidate all cache entries related to the filepath.
        """
        for key in list(self.cache.keys()):
            if key[0] == filepath:
                print(f"Invalidating cache of key: {key}")
                del self.cache[key]

    def send_generic_request(self, service_id, filepath, *additional_data):
        """
        Constructs and sends a request to the server based on specified parameters and service ID.
        """
        request_id = self.generate_request_id().encode('utf-8')
        filepath_bytes = filepath.encode('utf-8')

        message_parts = [
            struct.pack('!I', len(request_id)), 
            request_id, 
            struct.pack('!I', service_id), 
            struct.pack('!I', len(filepath_bytes)), 
            filepath_bytes 
        ]
        
        # Append additional data directly to message_parts
        for data in additional_data:
            if isinstance(data, bytes):
                message_parts.append(data)
            else:
                raise ValueError("additional_data elements must be bytes objects")

        # Combine all parts of the message
        message = b''.join(message_parts)

        if service_id == 1:  # Assuming 1 is the service_id for reading a file
            offset, length = additional_data
            cache_key = (filepath, struct.unpack('!I', offset)[0], struct.unpack('!I', length)[0])
        else:
            cache_key = None

        # Store the request details including the cache_key
        self.pending_requests[request_id] = {"send_time": time.time(), "data": message, "cache_key": cache_key}

        drop_rate = 0  # 30% chance to simulate a message drop
        if random.random() < drop_rate:
            print(f"Simulating drop of request to {filepath}")
            return  # Simulate drop by returning early
        self.client_socket.settimeout(10)
        self.client_socket.sendto(message, self.server_address)
        
        response, _ = self.client_socket.recvfrom(4096)
        if not response:
            print("Socket did not receive data or connection timed out")
            return None
        self.client_socket.settimeout(None)
        # Upon receiving a response, remove the request from pending_requests
        del self.pending_requests[request_id]
        return response


    def check_response(self, response, cache_key=None):
        """
        Processes the server's response to a request, updating the cache if necessary, and returns the success status.
        """
        if response:
            success, content = self.unpack_response(response)
            if success:
                # Update cache with new data
                if cache_key:  
                    self.cache[cache_key] = (content, time.time())
                message = content.decode('utf-8')
            else:
                message = "Error: " + content.decode('utf-8')
            self.display_response(message)
            return success
        return False


    def read_file(self):
        """
        Initiates a request to read a file from the server, including handling cached responses.
        """
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
                self.display_response(f"Reading from cache: {cached_data.decode('utf-8')}")
                return
        
        # If data is not in cache or is stale, fetch from server
        response = self.send_read_request(filepath, offset, length)
        self.check_response(response, cache_key)

    def send_read_request(self, filepath, offset, length):
        """
        Sends a read request to the server with the specified filepath, offset, and length.
        Both offset (as bytes) and length (as bytes) are passed as additional data.
        """
        # Offset and length needs to be packed as bytes since they are numerical values
        offset_bytes = struct.pack('!I', offset)
        length_bytes = struct.pack('!I', length)
        return self.send_generic_request(1, filepath, offset_bytes, length_bytes)
        

    def insert_content_to_file(self):
        """
        Sends a request to the server to insert content into a file at a specified offset.
        """
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

    def send_insert_request(self, filepath, offset, content):
        """
        Constructs and sends an insertion request to the server for a given file, offset, and content to insert.
        """
        # Offset needs to be packed as bytes since it's a numerical value
        offset_bytes = struct.pack('!I', offset)
        return self.send_generic_request(2, filepath, offset_bytes, content)
        

    def listen_for_updates(self):
        """
        Listens for updates from the server on files being monitored, displaying any received updates.
        """
        while True:
            try:
                response, _ = self.client_socket.recvfrom(4096)
                message = response.decode('utf-8')
                
                if(message[0:5] == "FALSE"):
                    self.display_response(f"Monitoring Update: {message[6:]}")
                    # Enable the buttons
                    self.read_button['state'] = 'normal'
                    self.insert_button['state'] = 'normal'
                    self.monitor_button['state'] = 'normal'  
                    self.delete_button['state'] = 'normal'
                    self.create_button['state'] = 'normal'
                    break
                print(f"Received message: {message}")  

                # Getting file path from message
                filepath = message.split(' updated: ')[0]

                # Invalidate cache entries related to the updated file
                self.invalidate_cache(filepath)

                self.display_response(f"Monitoring Update: {message}")

            except Exception as e:
                print(f"Stopped listening for monitoring updates: {e}")
                break

    def start_monitoring(self):
        """
        Sends a request to the server to start monitoring changes to a specified file.
        """
        filepath = self.monitor_filepath.get()
        interval = int(self.monitor_interval.get())
        response = self.send_monitor_request(filepath, interval)
        success, message = self.unpack_response(response)
        if success:
            # Listen for updates in a separate thread to avoid blocking the UI
            self.monitor_thread = threading.Thread(target=self.listen_for_updates, daemon=True)
            self.monitor_thread.start()
            message = message.decode('utf-8')
            # Disable the button
            self.read_button['state'] = 'disabled'
            self.insert_button['state'] = 'disabled'
            self.monitor_button['state'] = 'disabled'  
            self.delete_button['state'] = 'disabled'
            self.create_button['state'] = 'disabled'
        else:
            message = "Monitoring Error: " + message.decode('utf-8')
        self.display_response(message)

    def send_monitor_request(self, filepath, interval):
        """
        Constructs and sends a monitoring request to the server for a given file and monitoring interval.
        """
        # Interval needs to be packed as bytes since it's a numerical value
        interval_bytes = struct.pack('!I', interval)
        return self.send_generic_request(3, filepath, interval_bytes)


    def delete_file(self):
        """
        Initiates a request to delete a specified file from the server.
        """
        filepath = self.delete_filepath.get()
        response = self.send_delete_request(filepath)
        success, message = self.unpack_response(response)
        if success:
            message = "Deletion successful"
        else:
            message = "Error: " + message.decode('utf-8')
        self.display_response(message)

    def send_delete_request(self, filepath):
        """
        Constructs and sends a deletion request to the server for a given file.
        """
        return self.send_generic_request(4, filepath)
        
    def create_file(self):
        """
        Sends a request to the server to create a new file with a specified name.
        """
        filepath = self.create_filepath.get()
        response = self.send_create_request(filepath)
        success, message = self.unpack_response(response)
        if success:
            message = "Creation successful"
        else:
            message = "Error: " + message.decode('utf-8')
        self.display_response(message)
    
    def send_create_request(self, filepath):
        """
        Constructs and sends a creation request to the server for a given file.
        """
        return self.send_generic_request(5, filepath)
       
    
    def check_pending_requests(self):
        """
        Periodically checks and resends any requests that have not received a response within a certain timeout period.
        """
        while True:
            current_time = time.time()
            for request_id, request_details in list(self.pending_requests.items()):
                if current_time - request_details["send_time"] > 20:  # 5-second timeout
                    print(f"Resending request {request_id} due to timeout")
                    # Resend the request
                    self.client_socket.settimeout(5)
                    self.client_socket.sendto(request_details["data"], self.server_address)
                    response, _ = self.client_socket.recvfrom(4096)
                    if not response:
                        print("Resend request Socket did not receive data or connection timed out")
                        # Update the send time
                        request_details["send_time"] = current_time
                    else:
                        success = self.check_response(response, request_details["cache_key"])
                        if success:
                            print(f"Resend request {request_id} successful")
                            del self.pending_requests[request_id]
                        else:
                            request_details["send_time"] = current_time
                    self.client_socket.settimeout(None)
            time.sleep(10)  # Check every 1 seconds
        

def main():
    parser = argparse.ArgumentParser(description='Start client with specified freshness interval.')
    parser.add_argument('--freshness', type=int, default=30,
                        help='Freshness interval for the client cache (in seconds).')
    args = parser.parse_args()
    root = tk.Tk()
    gui = ClientGUI(root, freshness_interval=args.freshness)
    root.mainloop()

if __name__ == "__main__":
    main()