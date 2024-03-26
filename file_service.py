import struct

# Marshalling
def marshal_read_request(filepath, offset, length):
    filepath_bytes = filepath.encode('utf-8')
    message = struct.pack(f'!I{len(filepath_bytes)}sII', len(filepath_bytes), filepath_bytes, offset, length)
    return message

# Unmarshalling
def unmarshal_read_request(message):
    filepath_length = struct.unpack('!I', message[:4])[0]
    filepath, offset, length = struct.unpack(f'!{filepath_length}sII', message[4:])
    filepath = filepath.decode('utf-8')
    return filepath, offset, length
