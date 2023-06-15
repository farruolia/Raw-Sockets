import functools
import random
import signal
import socket
from struct import pack, unpack
import struct
import sys

# tcp constants
tcp_source_port = random.randint(10000, 60000)
tcp_dest_port = 80

def get_source_ip():
    """
    Method to get the source IP

    Returns:
        str: The source IP
    """

    socket_temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socket_temp.connect(('8.8.8.8', 80))
    ip_source = socket_temp.getsockname()[0]
    socket_temp.close()
    return ip_source

def calculate_checksum(data: bytes):
    """
    Method to calculate the checksum

    Args:
        data (bytes): The data on which we need to calculate checksum
    Returns:
        int: The checksum
    """

    sum = 0
    if len(data) % 2 == 1:
        data += struct.pack('B', 0)
    for i in range(0, len(data), 2):
        word = data[i+1] + (data[i] << 8)
        sum = sum + word
    sum = (sum >> 16) + (sum & 0xffff)
    sum = ~sum & 0xffff
    return sum

def verify_checksum(pseudo_packet: bytes, payload_length: int):
    """
    Method to verify checksum

    Args:
        pseudo_packet (bytes): The psuedo packet for calculating expected value
        payload_length (int): The length of the payload
    Returns:
        boolean: Is it the same as expected or not ?
    """

    # unpacking ip header
    ip_header = pseudo_packet[0:20]
    ip_header = unpack("!BBHHHBBH4s4s", ip_header)
    placeholder = 0
    tcp_length = ip_header[2] - 20
    protocol = ip_header[6]
    ip_source = ip_header[8]
    ip_dest = ip_header[9]

    # unpacking tcp header
    tcp_header = pseudo_packet[20:]
    unpack_format = '!HHLLBBHHH' + str(payload_length) + 's'

    if payload_length % 2 == 1:  
        payload_length += 1

    pack_format = '!HHLLBBHHH' + str(payload_length) + 's'
    tcp_header = unpack(unpack_format, tcp_header)
    received_checksum = tcp_header[7]
    
    tcp_segment = pack(pack_format, 
                       tcp_header[0], 
                       tcp_header[1], 
                       tcp_header[2], 
                       tcp_header[3], 
                       tcp_header[4], 
                       tcp_header[5], 
                       tcp_header[6], 
                       0, 
                       tcp_header[8], 
                       tcp_header[9])
    
    pseudo_header = pack('!4s4sBBH', ip_source, ip_dest, placeholder, protocol, tcp_length)     
    pseudo_packet = pseudo_header + tcp_segment
    tcp_checksum = calculate_checksum(pseudo_packet)

    return (received_checksum == tcp_checksum)

def create_GET(HOST_NAME: str, PATH_NAME: str):
    """
    The method to create the GET request to send to the server

    Args:
        HOST_NAME (str): The HOST NAME of the server
        PATH_NAME (str): The PATH NAME of the server
    Returns:
       str : the request
    """

    request = "GET " + PATH_NAME + " HTTP/1.0\r\n" + "Host: " + HOST_NAME + " \r\n\r\n"     
    return request

def write_to_file(http_response_dict: dict, PATH_NAME: str):
    """
    Method to write the bytes to file

    Args:
        http_response_dict (dict): The Ordered dictionary that holds all the bytes received from server
        PATH_NAME (str): The path name of the URL
    """

    http_response = b''

    for key in http_response_dict:
        http_response = http_response + http_response_dict[key]

    paths = PATH_NAME.split("/")
    filename = paths[len(paths) - 1]

    if not filename:
        filename = "index.html"
    index = open(filename, "wb+")
    header, response = http_response.split(b'\r\n\r\n', 2)

    if header.find(b'200 OK') == -1:
        print("200 status code not received")
        sys.exit(1)

    index.write(response)           
    index.close()

class TimeoutError(Exception):
    pass

def timeout(seconds, error_message = "Time out has occured"):
    """
    Timeout method

    Args:
        seconds (int): seconds
        error_message (str, optional): Error message. Defaults to "Time out has occured".
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            def timeout_handler():
                raise TimeoutError(error_message)
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(seconds)
            try:
                result_timeout = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result_timeout
        return wrapper
    return decorator