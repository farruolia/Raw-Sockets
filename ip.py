import random
import socket
from struct import pack, unpack
from utils import get_source_ip, calculate_checksum, timeout

ip_source = get_source_ip()
MAX_TIMEOUT = 180

class IPPacket:
    """
    Class that represents an IP packet
    """

    def __init__(self, HOST_NAME):
        """
        Initializes the class members
        
        Args:
            HOST_NAME (String): The host name of the destination
        """
        self.ip_version = 4
        self.ip_ihl = 5
        self.ip_tos = 0
        self.ip_total_len = 20
        self.ip_id = random.randint(10000,50000)
        self.ip_frag_off = 16384
        self.ip_ttl = 255
        self.ip_proto = socket.IPPROTO_TCP
        self.ip_checksum = 0
        self.ip_source = ip_source
        self.ip_dest = socket.gethostbyname(HOST_NAME)

    def create_IP_header(self, payload_length: int = 0):
        """
        Method to create the IP header
        Args:
            payload_length (int, optional): The length of the payload. Defaults to 0.
        Returns:
            bytes: ip header itself
        """
        ip_ihl_version = (self.ip_version << 4) + self.ip_ihl
        self.ip_total_len = self.ip_total_len + payload_length
        ip_source_addr = socket.inet_aton(self.ip_source)   
        ip_dest_addr = socket.inet_aton(self.ip_dest)
        ip_header = pack('!BBHHHBBH4s4s', 
                            ip_ihl_version, 
                            self.ip_tos, 
                            self.ip_total_len, 
                            self.ip_id, 
                            self.ip_frag_off, 
                            self.ip_ttl, 
                            self.ip_proto, 
                            self.ip_checksum, 
                            ip_source_addr, 
                            ip_dest_addr)
        self.ip_checksum = calculate_checksum(ip_header)
        ip_header = pack('!BBHHHBBH4s4s', 
                            ip_ihl_version, 
                            self.ip_tos, 
                            self.ip_total_len, 
                            self.ip_id, 
                            self.ip_frag_off, 
                            self.ip_ttl, 
                            self.ip_proto, 
                            self.ip_checksum, 
                            ip_source_addr, 
                            ip_dest_addr)
        return ip_header
    
    def send(self, sender_socket: socket, tcp_header, tcp_length: int, data: str = ""):
        """
        Method to send the packet

        Args:
            sender_socket (socket): The sender socket
            tcp_header (bytes): The TCP header
            tcp_length (int): The length of the TCP header
            data (str, optional): The data itself. Defaults to "".
        """

        packet = self.create_IP_header(tcp_length) + tcp_header + data.encode()
        sender_socket.sendto(packet, (self.ip_dest, 0))

    @timeout(MAX_TIMEOUT, "Timeout happens if data is not received")
    def receive(self, receiver_socket: socket):
        """
        Method to receive a packet and unpack it

        Args:
            receiver_socket (socket): The receiver socket
        Returns:
            bytes: the unpacked, received packet
        """

        received_ip_source = ""
        while (received_ip_source != str(self.ip_dest)):
            received_packet = receiver_socket.recv(65565)
            ip_header_temp = received_packet[0:20]
            ip_header = unpack("!2sH8s4s4s", ip_header_temp)     
            received_ip_source = socket.inet_ntoa(ip_header[3])
        return received_packet