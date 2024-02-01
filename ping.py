import socket

ICMP_MODE = socket.getprotobyname("icmp")
PACKET_SIZE = 64
WAIT_TIMEOUT = 3.0

class Ping:
    def __init__(self):
        self.server_socket = self.create_socket()

    def create_socket(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_MODE)
        except socket.error as e:
            print(f"failed. (socket error: {e.args[1]})")
            raise

        return server_socket

    def calculate_ping(self, hostname):
        try:
            destination_ip = socket.gethostbyname(hostname)
            print(f"Ping {hostname}")
            print(f"Destination IP: {destination_ip}")
            print(f"Packet size: {PACKET_SIZE}")
        except socket.gaierror as e:
            print(f"\nError: Unknown host: {hostname} ({e.args[1]})")
            return
