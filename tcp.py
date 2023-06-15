import socket
import struct
import sys
from ip import IPPacket
from utils import calculate_checksum, tcp_source_port, tcp_dest_port, timeout, TimeoutError

MAX_TIMEOUT = 60

class TCPPacket:

    """
    Class that represents TCP packets
    """

    def __init__(self, HOST_NAME):
        """
        Initialises the class members when the object is created

        Args:
            HOST_NAME (str): The HOST_NAME of the server
        """
        self.ip_packet = IPPacket(HOST_NAME)
        self.tcp_doff = 5
        self.tcp_rst_flag = 0
        self.tcp_urg_flag = 0
        self.tcp_window = socket.htons(60000)	
        self.tcp_checksum = 0
        self.tcp_urg_ptr = 0
        self.tcp_header = []

    def create_TCP_header(self, tcp_seq_no: int = 0, tcp_ack_no: int = 0, tcp_syn_flag: int = 0, tcp_ack_flag: int = 0, tcp_fin_flag: int = 0, tcp_psh_flag: int = 0, data: str = ""):
        """
        Creates TCP header

        Args:
            tcp_seq_no (int, optional): Sequence number for TCP header. Defaults to 0
            tcp_ack_no (int, optional): Acknowledgment number for TCP header. Defaults to 0
            tcp_syn_flag (int, optional): SYN flag for TCP header. Defaults to 0
            tcp_ack_flag (int, optional): ACK flag for TCP header. Defaults to 0
            tcp_fin_flag (int, optional): FIN flag for TCP header. Defaults to 0
            tcp_psh_flag (int, optional): PSH flag for TCP header. Defaults to 0
            data (str, optional): Data to be sent. Defaults to "".

        Returns:
            self.tcp_header (bytes): TCP header
            (int): TCP length
        """
        tcp_offset_res = (self.tcp_doff << 4) + 0
        tcp_flags = tcp_fin_flag + (tcp_syn_flag << 1) + (self.tcp_rst_flag << 2) + (tcp_psh_flag <<3) + (tcp_ack_flag << 4) + (self.tcp_urg_flag << 5)

        self.tcp_header = struct.pack('!HHLLBBHHH', 
                            tcp_source_port, 
                            tcp_dest_port, 
                            tcp_seq_no, 
                            tcp_ack_no, 
                            tcp_offset_res, 
                            tcp_flags,  
                            self.tcp_window, 
                            self.tcp_checksum, 
                            self.tcp_urg_ptr)

        # pseudo header for checksum calculation
        ip_source_pseudo = socket.inet_aton(self.ip_packet.ip_source)
        ip_dest_pseudo = socket.inet_aton(self.ip_packet.ip_dest)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(self.tcp_header) + len(data)
        pseudo_ip_header = struct.pack('!4s4sBBH', 
                                    ip_source_pseudo, 
                                    ip_dest_pseudo, 
                                    placeholder, 
                                    protocol, 
                                    tcp_length)
        pseudo_ip_header = pseudo_ip_header + self.tcp_header + data.encode()

        self.tcp_checksum = calculate_checksum(pseudo_ip_header)

        # actual TCP header with correct checksum
        self.tcp_header = struct.pack('!HHLLBBHHH', 
                            tcp_source_port, 
                            tcp_dest_port, 
                            tcp_seq_no, 
                            tcp_ack_no, 
                            tcp_offset_res, 
                            tcp_flags,  
                            self.tcp_window, 
                            self.tcp_checksum, 
                            self.tcp_urg_ptr)

        return self.tcp_header, 20 + len(data)
    
    def send(self, sender_socket: socket, tcp_seq_no: int, tcp_ack_no: int, tcp_syn_flag: int, tcp_ack_flag: int, tcp_fin_flag: int = 0, tcp_psh_flag: int = 0, data: str = ""):
        """
        Sends the packet

        Args:
            sender_socket (socket): Sender socket object
            tcp_seq_no (int): Sequence number for TCP header
            tcp_ack_no (int): Acknowledgment number for TCP header
            tcp_syn_flag (int): SYN flag for TCP header
            tcp_ack_flag (int): ACK flag for TCP header
            tcp_fin_flag (int, optional): FIN flag for TCP header. Defaults to 0.
            tcp_psh_flag (int, optional): PSH flag for TCP header. Defaults to 0.
            data (str, optional): Data to be sent. Defaults to "".
        """
        tcp_header, tcp_length = self.create_TCP_header(tcp_seq_no, tcp_ack_no, tcp_syn_flag, tcp_ack_flag, tcp_fin_flag, tcp_psh_flag, data)
        self.ip_packet.send(sender_socket, tcp_header, tcp_length, data)

    def receive(self, receiver_socket: socket):
        """
        Receives the packet

        Args:
            receiver_socket (socket): Receiver socket object

        Returns:
            received_packet (socket): Received packet
        """
        try:
            received_packet = self.ip_packet.receive(receiver_socket)
        except TimeoutError:
            print("No data received for a long time, dead connection!")
            sys.exit(-1)
        return received_packet
    
class TCPConnection:
    """
    Class that represents TCP connection
    """

    def __init__(self, HOST_NAME):
        """
        Initialises when the object is created
        Args:
            HOST_NAME (str): The HOST_NAME of the server
        """
        self.HOST_NAME = HOST_NAME

    @timeout(MAX_TIMEOUT, "Timeout happens if ack is not received")
    def verify_ack_handshake(self, receiver_socket: socket, tcp_seq_no: int, tcp_header_max: int = 40):
        """
        Verifies the ACK from the server in the handshake 

        Args:
            receiver_socket (socket): Reciver socket object
            tcp_seq_no (int): Sequence number for TCP header
            tcp_header_max (int, optional): TCP maximum header. Defaults to 40.

        Returns:
            (boolean/ int): False/ TCP Sequence number
            mss (int): Maximum segment size
        """
        tcp_packet = TCPPacket(self.HOST_NAME)
        
        received_packet = tcp_packet.receive(receiver_socket)

        ip_header = struct.unpack("!2sH8s4s4s", received_packet[0:20])
        length = ip_header[1] - 40 

        # maximum segment size
        mss = 0

        unpack_format = '!HHLLBBHHH'
        if tcp_header_max == 44:
            # for SYN/ACK segment which is of 24 bytes
            unpack_format = unpack_format + 'L' 

        tcp_header = struct.unpack(unpack_format, received_packet[20:tcp_header_max])
        
        seq_no_recv_received = tcp_header[2]
        ack_no_recv_received = tcp_header[3]
        tcp_flags_received = tcp_header[5]
        
        if length == 0 or length == 4: 
            seq_no_recv_received = tcp_header[2]
            ack_no_recv_received = tcp_header[3]
            tcp_flags_received = tcp_header[5]
            
            if tcp_header_max == 44:
                mss = tcp_header[9] 
            tcp_ack_flag_received = (tcp_flags_received & 16)
            if tcp_ack_flag_received == 16 and ((tcp_seq_no == ack_no_recv_received - 1 and length == 4) or (tcp_seq_no == ack_no_recv_received and length == 0)):
                return seq_no_recv_received, mss
        return False, mss

    def three_way_handshake(self, sender_socket: socket, receiver_socket: socket):
        """
        Performs the three-way handshake, sending the SYN and ACK from the client, and calling the verification for the SYN/ACK from the server

        Args:
            sender_socket (socket): Sender socket object
            receiver_socket (socket): Reciver socket object

        Returns:
            (int): TCP Sequence number
            tcp_ack_no_received (int): TCP acknowledgment number
            mss (int): MAximum segment size
        """

        # sending SYN to the server
        tcp_seq_no = 0
        tcp_ack_no = 0
        tcp_syn_flag = 1
        tcp_ack_flag = 0
        
        tcp_packet = TCPPacket(self.HOST_NAME)
        tcp_packet.send(sender_socket, tcp_seq_no, tcp_ack_no, tcp_syn_flag, tcp_ack_flag)

        # checking whether we get a SYN/ACK from the server 
        try:
            tcp_ack_no_received, mss = self.verify_ack_handshake(receiver_socket, tcp_seq_no, 44)
        except TimeoutError:
            tcp_packet.send(sender_socket, tcp_seq_no, tcp_ack_no, tcp_syn_flag, tcp_ack_flag)
            try:
                tcp_ack_no_received, mss = self.verify_ack_handshake(receiver_socket, tcp_seq_no, 44)
            except TimeoutError:
                print("Failed to create a TCP connection")
                sys.exit(-1)
                
        # in case we don't receive a SYN/ACK
        if not tcp_ack_no_received:  
            print("handshake failed!\n")
            sys.exit(1)
        else:
            # sending an ACK back to the server, and completing the handshake
            tcp_seq_no = 1 
            tcp_syn_flag = 0
            tcp_ack_flag = 1

            tcp_packet = TCPPacket(self.HOST_NAME)
            tcp_packet.send(sender_socket, tcp_seq_no, tcp_ack_no_received + 1, tcp_syn_flag, tcp_ack_flag)
            
            return 1, tcp_ack_no_received, mss

    @timeout(MAX_TIMEOUT, "Timeout happens if ack is not received")
    def verify_ack(self, receiver_socket: socket, tcp_seq_no: int, tcp_header_max: int = 40, payload_length: int = 0):
        """
        Verifies the ACKs from the server

        Args:
            receiver_socket (socket): Reciver socket object
            tcp_seq_no (int): Sequence number for TCP header
            tcp_header_max (int, optional): TCP maximum header. Defaults to 40.
            payload_length (int, optional): Length of data. Defaults to 0.

        Returns:
            (boolean/ int): False/ TCP Sequence number
            mss (int): Maximum segment size
        """

        tcp_packet = TCPPacket(self.HOST_NAME)
        received_packet = tcp_packet.receive(receiver_socket)
        
        # maximum segment size
        mss = 0
        
        tcp_header = struct.unpack('!HHLLBBHHH', received_packet[20:tcp_header_max])
        
        tcp_seq_no_received = tcp_header[2]
        tcp_ack_no_received = tcp_header[3]
        tcp_flags_received = tcp_header[5]
        tcp_ack_flag_received = (tcp_flags_received & 16)

        if (tcp_ack_no_received - payload_length == tcp_seq_no and tcp_ack_flag_received == 16):
            return tcp_seq_no_received, mss

        return False, mss

    @timeout(MAX_TIMEOUT, "Timeout happens if ack is not received")
    def verify_ack_fin(self, receiver_socket: socket, tcp_seq_no: int, tcp_header_max: int = 40):
        """
        Verfies the FIN/ACK from the server

        Args:
            receiver_socket (socket): Reciver socket object
            tcp_seq_no (int): Sequence number for TCP header
            tcp_header_max (int, optional): TCP maximum header. Defaults to 40.

        Returns:
            (boolean/ int): False/ TCP Sequence number
            mss (int): Maximum segment size
        """

        tcp_packet = TCPPacket(self.HOST_NAME)
        received_packet = tcp_packet.receive(receiver_socket)

        # maximum segment size
        mss = 0
        
        tcp_header = struct.unpack('!HHLLBBHHH', received_packet[20:tcp_header_max])
        
        tcp_seq_no_received = tcp_header[2]
        tcp_ack_no_received = tcp_header[3]
        tcp_flags_received = tcp_header[5]
        tcp_ack_flag_received = (tcp_flags_received & 16)

        if (tcp_seq_no + 1 == tcp_ack_no_received and tcp_ack_flag_received == 16):
            return tcp_seq_no_received, tcp_ack_no_received, mss
        
        return False, mss