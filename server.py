import socket
import struct
import time
from threading import Thread, Lock


def read_file_content(filepath, offset, length):
    """Reads a specific portion of a file."""
    try:
        with open(filepath, 'rb') as file:
            file.seek(offset)
            content = file.read(length)
            return True, content  # Success flag and content
    except FileNotFoundError:
        return False, b"File not found"
    except Exception as e:
        return False, str(e).encode()

def process_request(data):
    """Process incoming client requests."""
    try:
        _, filepath_length = struct.unpack('!II', data[:8])
        filepath, offset, length = struct.unpack(f'!{filepath_length}sII', data[8:])
        filepath = filepath.decode('utf-8')
        success, content = read_file_content(filepath, offset, length)
        return struct.pack('!?I', success, len(content)) + content
    except struct.error:
        return struct.pack('!?I', False, 0) + b"Invalid request format"

def handle_request(data, client_address):
    # Some logic to determine the type of request and process it
    # Let's assume data starts with an integer indicating the request type
    request_type, = struct.unpack('!I', data[:4])

    if request_type == 1:  # Example request type 1
        response = process_type_1_request(data)
    elif request_type == 2:  # Example request type 2
        response = process_type_2_request(data)
    else:
        response = b"Error: Unknown request type"

    return response

def process_type_1_request(data):
    # Process the request and return a bytes object
    # Be sure every code path in this function returns bytes
    return b"Response for type 1"

def process_type_2_request(data):
    # Process the request and return a bytes object
    # Be sure every code path in this function returns bytes
    return b"Response for type 2"


def start_server(port=2222):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("localhost", 2222))
    print("Server listening on port 2222")

    try:
        while True:
            message, client_address = server_socket.recvfrom(1024)
            response = handle_request(message, client_address)
            if response is not None:
                server_socket.sendto(response, client_address)
            else:
                print("Warning: No response generated for a request.")
    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        server_socket.close()

def insert_file_content(filepath, offset, content):
    """Insert content into a file at the specified offset."""
    try:
        # Read original content
        with open(filepath, 'r+b') as file:
            file.seek(offset)
            original_content = file.read()
            file.seek(offset)
            file.write(content + original_content)  # Insert new content and push forward the original content
        return True, b"Insertion successful"
    except FileNotFoundError:
        return False, b"File not found"
    except Exception as e:
        return False, str(e).encode()

# Extend process_request to handle the insert request
def process_request(data):
    service_id, = struct.unpack('!I', data[:4])
    if service_id == 1:  # Read service (existing code)
        pass  # Existing read logic here
    elif service_id == 2:  # Insert service
        _, filepath_length = struct.unpack('!II', data[:8])
        expected_end_of_data = 8 + filepath_length + 4 + 4  # start + filepath + offset + content_length
        if len(data) < expected_end_of_data:
            # Handle error: Data is shorter than expected
            return struct.pack('!?I', False, 0) + b"Invalid request format"

        unpack_format = f'!{filepath_length}sII'
        filepath, offset, content_length = struct.unpack(unpack_format, data[8:8 + filepath_length + 8])
        content = data[8 + filepath_length + 8:]
        filepath = filepath.decode('utf-8')
        success, response_message = insert_file_content(filepath, offset, content)
        return struct.pack('!?I', success, len(response_message)) + response_message

# Global dictionary to keep track of monitored files and their clients
monitored_files = {}
lock = Lock()

def handle_monitor_expiration(filepath, client_info):
    with lock:
        monitored_files[filepath].remove(client_info)
        if not monitored_files[filepath]:
            del monitored_files[filepath]

def update_monitored_clients(filepath, content):
    with lock:
        if filepath in monitored_files:
            for client_address, expiration_time in monitored_files[filepath]:
                if time.time() < expiration_time:
                    notify_client(content, client_address)
                else:
                    handle_monitor_expiration(filepath, (client_address, expiration_time))

def notify_client(content, client_address):
    # Function to notify client. This could be more complex in a real application.
    pass

def monitor_service(data, client_address):
    # Unpack data for filepath and monitor interval
    filepath_length = struct.unpack('!I', data[:4])[0]
    filepath, interval = struct.unpack(f'!{filepath_length}sI', data[4:4+filepath_length+4])
    filepath = filepath.decode('utf-8')
    expiration_time = time.time() + interval

    # Register client for monitoring
    with lock:
        if filepath in monitored_files:
            monitored_files[filepath].append((client_address, expiration_time))
        else:
            monitored_files[filepath] = [(client_address, expiration_time)]

    # Start a thread to remove the client after the interval expires
    Thread(target=handle_monitor_expiration, args=(filepath, (client_address, expiration_time))).start()

if __name__ == "__main__":
    start_server()
