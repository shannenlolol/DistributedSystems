import socket
import struct
import time
import datetime
import os
import argparse
import random

# Parse command-line arguments to determine invocation semantics
parser = argparse.ArgumentParser(description='Start server with specified invocation semantics.')
parser.add_argument('--semantics', choices=['at-least-once', 'at-most-once'], required=True,
                    help='Invocation semantics to be used by the server (at-least-once or at-most-once).')
args = parser.parse_args()

invocation_semantics = args.semantics
print(f"Server starting with {invocation_semantics} semantics.")

# Tracks (request_id, client_address) -> response
# This is to avoid re-executing operations for at-most-once semantics
processed_requests = {}

monitored_files = {}  # {filepath: [(client_address, expiration_time), ...]}

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

def insert_file_content(filepath, offset, content):
    """Insert content into a file at the specified offset."""
    try:
        with open(filepath, 'r+b') as file:
            file.seek(offset)
            original_content = file.read()
            file.seek(offset)
            file.write(content + original_content)  # Insert new content and push forward the original content
        # Notify monitoring clients about the update
        notify_monitored_clients(filepath)
        return True, b"Insertion successful"
    except FileNotFoundError:
        return False, b"File not found"
    except Exception as e:
        return False, str(e).encode()

def notify_monitored_clients(filepath, delete=False):
    """Notifies clients monitoring the specified file about its update."""
    current_time = time.time()
    clients_to_notify = monitored_files.get(filepath, [])
    for client_address, expiration_time in clients_to_notify:
        if expiration_time > current_time:
            try:
                if delete == False:
                    with open(filepath, 'rb') as file:
                        content = file.read()
                        update_message = f"{filepath} updated: {content}".encode('utf-8')  # Encoding the message with the file's content
                        print(f"Sending to {client_address} updated content for {filepath} - {update_message}")
                        server_socket.sendto(update_message, client_address)
                else:
                    update_message = f"{filepath} deleted".encode('utf-8')
                    print(f"Sending to {client_address} updated content for {filepath} - {update_message}")
                    server_socket.sendto(update_message, client_address)
            except Exception as e:
                print(f"Error notifying client {client_address}: {e}")

def delete_file_content(filepath):
    """Deletes a specified file."""
    try:
        os.remove(filepath)
        notify_monitored_clients(filepath, delete=True)
        return True, b"Deletion successful"
    except FileNotFoundError:
        return False, b"File not found"
    except Exception as e:
        return False, str(e).encode()

# Add this new function in the server script
def create_file_content(filepath):
    """Creates a new file."""
    try:
        # Open the file in write mode which will create the file if it does not exist
        with open(filepath, 'w') as file:
            pass  # Just opening and closing the file is enough to create it
        return True, b"Creation successful"
    except Exception as e:
        return False, str(e).encode()
    
def process_request(data, client_address):
    # Unpack the first integer to get the length of request_id
    request_id_length = struct.unpack('!I', data[:4])[0]
    # Calculate where the request_id itself ends
    request_id_end = 4 + request_id_length
    request_id = data[4:request_id_end].decode('utf-8')  # Assuming you want to use the request_id as a string

    # Now unpack service_id which follows request_id
    service_id = struct.unpack('!I', data[request_id_end:request_id_end + 4])[0]

    # Next, we need to find the length of the filepath
    filepath_length_start = request_id_end + 4
    filepath_length = struct.unpack('!I', data[filepath_length_start:filepath_length_start + 4])[0]

    # Unpack filepath
    filepath_start = filepath_length_start + 4
    filepath_end = filepath_start + filepath_length
    filepath = data[filepath_start:filepath_end].decode('utf-8')

    # For at-most-once semantics, check if the request has been processed before
    if invocation_semantics == "at-most-once" and request_id in processed_requests:
        return processed_requests[request_id]
    print(f"{datetime.datetime.now()} Received ServiceId {service_id} request from {client_address}")
    if service_id == 1:  # Read service
        additional_data_start = filepath_end
        offset, length = struct.unpack('!II', data[additional_data_start:additional_data_start + 8])
        success, content = read_file_content(filepath, offset, length)
        response = struct.pack('!?I', success, len(content)) + content

    elif service_id == 2:  # Insert service
        # For Insert, we expect offset (4 bytes) and content to follow filepath
        offset, = struct.unpack('!I', data[filepath_end:filepath_end + 4])
        content_start = filepath_end + 4
        content = data[content_start:]
        success, message = insert_file_content(filepath, offset, content)
        response = struct.pack('!?I', success, len(message)) + message
    
    elif service_id == 3:  # Monitor service
        # For Monitor, we expect interval (4 bytes) to follow filepath
        interval, = struct.unpack('!I', data[filepath_end:filepath_end + 4])
        expiration_time = time.time() + interval
        monitored_files.setdefault(filepath, []).append((client_address, expiration_time))

        success = True  # The operation to start monitoring is always successful
        ack_message = f"Monitoring {filepath} for {interval} seconds"
        response_message = ack_message.encode('utf-8')

        response = struct.pack('!?I', success, len(response_message)) + response_message
    
    elif service_id == 4:  # Delete service
        # Delete only uses the filepath, which has been unpacked earlier
        success, message = delete_file_content(filepath)
        response = struct.pack('!?I', success, len(message)) + message
    
    elif service_id == 5:  # Create service
        # Create only uses the filepath, similar to Delete
        success, message = create_file_content(filepath)
        response = struct.pack('!?I', success, len(message)) + message

    else:
        response = struct.pack('!?I', False, 0) + b"Unknown service ID"

    # For at-most-once semantics, remember the response for this request
    if invocation_semantics == "at-most-once":
        processed_requests[request_id] = response

    return response


def start_server(port=2222):
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('', port))
    print(f"Server listening on port {port} using {invocation_semantics} semantics.")

    try:
        while True:
            data, client_address = server_socket.recvfrom(4096)
            response = process_request(data, client_address)
            drop_rate = 1  # 30% chance to simulate a message drop
            if random.random() < drop_rate:
                print(f"Simulating drop of request from {client_address}")
            else:
                if response:
                    server_socket.sendto(response, client_address)
    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()