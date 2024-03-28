import socket
import struct
import time

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

def notify_monitored_clients(filepath):
    """Notifies clients monitoring the specified file about its update."""
    current_time = time.time()
    clients_to_notify = monitored_files.get(filepath, [])
    for client_address, expiration_time in clients_to_notify:
        if expiration_time > current_time:
            try:
                with open(filepath, 'rb') as file:
                    content = file.read()
                    server_socket.sendto(content, client_address)
            except Exception as e:
                print(f"Error notifying client {client_address}: {e}")
                
# Extend process_request to handle the insert request
def process_request(data, client_address):
    service_id, = struct.unpack('!I', data[:4])
    if service_id == 1:  # Read service (existing code)
        try:
            _, filepath_length = struct.unpack('!II', data[:8])
            filepath, offset, length = struct.unpack(f'!{filepath_length}sII', data[8:])
            filepath = filepath.decode('utf-8')
            success, content = read_file_content(filepath, offset, length)
            return struct.pack('!?I', success, len(content)) + content
        except struct.error:
            return struct.pack('!?I', False, 0) + b"Invalid request format"

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
    
    elif service_id == 3:  # Monitor service
        try:
            # Unpack the filepath length right after the service_id
            _, filepath_length = struct.unpack('!II', data[:8])
            
            # Ensure there is enough data for the filepath plus the interval
            if len(data) < (8 + filepath_length + 4):
                print("Data too short for expected format.")
                error_message = "Error processing your monitoring request: Incomplete data.".encode()
                server_socket.sendto(error_message, client_address)
                return
            
            # Unpack the filepath using its length
            filepath_format = f'!{filepath_length}s'
            start_of_filepath = 8  # Starting byte of filepath data
            end_of_filepath = start_of_filepath + filepath_length  # Ending byte of filepath data
            filepath, = struct.unpack(filepath_format, data[start_of_filepath:end_of_filepath])
            filepath = filepath.decode('utf-8')
            
            # Unpack the interval that follows immediately after the filepath
            interval_format = '!I'
            interval, = struct.unpack(interval_format, data[end_of_filepath:end_of_filepath + 4])
            
            # Register client for monitoring...
            expiration_time = time.time() + interval
            monitored_files.setdefault(filepath, []).append((client_address, expiration_time))
            ack_message = f"Monitoring {filepath} for {interval} seconds".encode()
            print(f"Sending message: {ack_message}")
            server_socket.sendto(ack_message, client_address)

        except struct.error as e:
            print(f"Struct error during unpacking: {e}")


def start_server(port=2222):
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('', port))
    print(f"Server listening on port {port}")

    try:
        while True:
            message, client_address = server_socket.recvfrom(4096)
            response = process_request(message, client_address)
            if response:
                server_socket.sendto(response, client_address)
    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()