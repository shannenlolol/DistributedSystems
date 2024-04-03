import socket
import struct
import threading
import time
from datetime import datetime
import os
import argparse
import random

# Parse command-line arguments to determine invocation semantics
parser = argparse.ArgumentParser(description='Start server with specified invocation semantics.')
parser.add_argument('--semantics', choices=['at-least-once', 'at-most-once'], required=True,
                    help='Invocation semantics to be used by the server (at-least-once or at-most-once).')
args = parser.parse_args()

invocation_semantics = args.semantics

# Tracks (request_id, client_address) -> response
# This is to avoid re-executing operations for at-most-once semantics
processed_requests = {}

# For simulation of drop messages, tracks how many times a request is received
simulate_drop_request_count = {} 

# {filepath: [(client_address, expiration_time), ...]}
monitored_files = {} 

def read_file_content(filepath, offset, length):
    """
    Reads a specific portion of a file at the specified offset and length.
    """
    try:
        with open(filepath, 'rb') as file:
            file.seek(offset)
            content = file.read(length)
            return True, content
    except FileNotFoundError:
        return False, b"File not found"
    except Exception as e:
        return False, str(e).encode()

def insert_file_content(filepath, offset, content):
    """
    Insert content into a file at the specified offset and notifies any monitoring clients.
    """
    try:
        with open(filepath, 'r+b') as file:
            file.seek(offset)
            original_content = file.read()
            file.seek(offset)
            file.write(content + original_content)
        notify_monitored_clients(filepath)
        return_message = f"Insertion of content to {filepath} at offset {offset} successful"
        return True, return_message.encode()
    except FileNotFoundError:
        return False, b"File not found"
    except Exception as e:
        return False, str(e).encode()

def notify_monitored_clients(filepath, delete=False):
    """
    Notifies clients monitoring the specified file about its update.
    """
    current_time = time.time()
    clients_to_notify = monitored_files.get(filepath, [])
    for client_address, expiration_time in clients_to_notify:
        if expiration_time > current_time:
            try:
                if delete == False: # If Update is not File Delete
                    with open(filepath, 'rb') as file:
                        content = file.read()
                        update_message = f"{filepath} updated: {content}".encode('utf-8')
                        print(f"{datetime.now().strftime('%d-%m-%Y %H:%M:%S')} Sending to {client_address} updated content for {filepath} - {update_message}")
                        server_socket.sendto(update_message, client_address)
                else:
                    update_message = f"{filepath} deleted".encode('utf-8')
                    print(f"{datetime.now().strftime('%d-%m-%Y %H:%M:%S')} Sending to {client_address} updated content for {filepath} - {update_message}")
                    server_socket.sendto(update_message, client_address)
            except Exception as e:
                print(f"{datetime.now().strftime('%d-%m-%Y %H:%M:%S')} Error notifying client {client_address}: {e}")

def delete_file_content(filepath):
    """
    Deletes a specified file.
    """
    try:
        os.remove(filepath)
        notify_monitored_clients(filepath, delete=True)
        return_message = f"Deletion of {filepath} successful"
        return True, return_message.encode()
    except FileNotFoundError:
        return False, b"File not found"
    except Exception as e:
        return False, str(e).encode()

def create_file_content(filepath):
    """
    Creates a new file at the specified filepath.
    """
    try:
        with open(filepath, 'w') as file:
            pass
        return_message = f"Creation of {filepath} successful"
        return True, return_message.encode()
    except Exception as e:
        return False, str(e).encode()

def monitor_end_thread(filepath, client_address, duration):
    """
    Monitors the specified file for a certain duration and sends a notification to the client upon expiration.
    """
    time.sleep(duration)
    update_message = f"FALSE Monitoring {filepath} shutting down".encode('utf-8')
    print(f"{datetime.now().strftime('%d-%m-%Y %H:%M:%S')} Sending to {client_address} updated content for {filepath} - {update_message}")
    server_socket.sendto(update_message, client_address)

def process_request(data, client_address):
    """
    Processes the incoming request from a client and executes the corresponding service.
    """

    # Unpack the first integer to get the length of request_id
    request_id_length = struct.unpack('!I', data[:4])[0]
    # Calculate where the request_id itself ends
    request_id_end = 4 + request_id_length
    request_id = data[4:request_id_end].decode('utf-8')

    # Unpack service_id which follows request_id
    service_id = struct.unpack('!I', data[request_id_end:request_id_end + 4])[0]

    # Length of the filepath
    filepath_length_start = request_id_end + 4
    filepath_length = struct.unpack('!I', data[filepath_length_start:filepath_length_start + 4])[0]

    # Unpack filepath
    filepath_start = filepath_length_start + 4
    filepath_end = filepath_start + filepath_length
    filepath = data[filepath_start:filepath_end].decode('utf-8')

    if simulate_drop_request_count.get(request_id, False):
        simulate_drop_request_count[request_id] += 1
    else: 
        simulate_drop_request_count[request_id] = 1
        drop_rate = 0  # Simulation: Chance that a message is dropped
        if random.random() < drop_rate:
            print(f"{datetime.now().strftime('%d-%m-%Y %H:%M:%S')} Simulating drop of request from {client_address}")
            return

    # For at-most-once semantics, check if the request has been processed before
    if invocation_semantics == "at-most-once" and request_id in processed_requests:
        return processed_requests[request_id]
    print(f"{datetime.now().strftime('%d-%m-%Y %H:%M:%S')} Received ServiceId {service_id} request from {client_address}")


    if service_id == 1:  # Read service
        additional_data_start = filepath_end
        # For Insert, offset (4 bytes) and length to follow filepath
        offset, length = struct.unpack('!II', data[additional_data_start:additional_data_start + 8])
        success, content = read_file_content(filepath, offset, length)
        response = struct.pack('!?I', success, len(content)) + content

    elif service_id == 2:  # Insert service
        # For Insert, offset (4 bytes) and content to follow filepath
        offset, = struct.unpack('!I', data[filepath_end:filepath_end + 4])
        content_start = filepath_end + 4
        content = data[content_start:]
        success, message = insert_file_content(filepath, offset, content)
        response = struct.pack('!?I', success, len(message)) + message
    
    elif service_id == 3:  # Monitor service
        # Check if the file exists
        if os.path.exists(filepath):
            # For Monitor, interval (4 bytes) to follow filepath
            interval, = struct.unpack('!I', data[filepath_end:filepath_end + 4])
            expiration_time = time.time() + interval
            monitored_files.setdefault(filepath, []).append((client_address, expiration_time))

            success = True 
            ack_message = f"Monitoring {filepath} for {interval} seconds"
            response_message = ack_message.encode('utf-8')
            end_thread = threading.Thread(target=monitor_end_thread, args=(filepath, client_address, interval))
            end_thread.daemon = True
            end_thread.start()
        else:
            # File not found
            success = False
            response_message = b"File Not Found"
            
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

    # For at-most-once semantics, remember the response for this requestId
    if invocation_semantics == "at-most-once":
        processed_requests[request_id] = response

    return response


def start_server(port=2222):
    """
    Starts the UDP server to listen for incoming requests.
    """
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('', port))
    print(f"{datetime.now().strftime('%d-%m-%Y %H:%M:%S')} Server listening on port {port} using {invocation_semantics} semantics.")

    try:
        while True:
            data, client_address = server_socket.recvfrom(4096)
            response = process_request(data, client_address)
            if response:
                server_socket.sendto(response, client_address)
    except KeyboardInterrupt:
        print(f"{datetime.now().strftime('%d-%m-%Y %H:%M:%S')} Server shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()