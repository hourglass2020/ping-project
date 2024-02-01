import socket
import struct
import sys
import time
import os

default_timer = time.time

ICMP_MODE = socket.getprotobyname("icmp")
PACKET_SIZE = 64
WAIT_TIMEOUT = 3000.0
MAX_SLEEP = 1000

ICMP_ECHO_REPLY = 0  # Echo reply (per RFC792)
ICMP_ECHO = 8  # Echo request (per RFC792)
ICMP_MAX_RECV = 2048  # Max size of incoming buffer


class Ping:
    def __init__(self, packet_num, hostname):
        self.destination_ip = None
        self.server_socket = self.create_socket()
        self.packet_num = packet_num
        self.hostname = hostname

    def create_socket(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_MODE)
        except socket.error as e:
            print(f"failed. (socket error: {e.args[1]})")
            raise

        return server_socket

    def calculate_ping(self):
        try:
            self.destination_ip = socket.gethostbyname(self.hostname)
            print(f"Ping {self.hostname}")
            print(f"Destination IP: {self.destination_ip}")
            print(f"Packet size: {PACKET_SIZE}")
        except socket.gaierror as e:
            print(f"\nError: Unknown host: {self.hostname} ({e.args[1]})")
            return

        sequence_count = 0

        for _ in range(self.packet_num):
            delay = self.get_ping(sequence_count)

            if delay is None:
                delay = 0

            sequence_count += 1

            if MAX_SLEEP > delay:
                time.sleep((MAX_SLEEP - delay) / 1000)

    def get_ping(self, sequence_count):
        delay = None

        my_id = os.getpid() & 0xFFFF

        sent_time = self.send_one_ping(my_id, sequence_count)

        if sent_time is None:
            self.server_socket.close()
            return None

        return delay

    def send_one_ping(self, my_id, my_seq_number):
        my_checksum = 0

        header = struct.pack("!BBHHH", ICMP_ECHO, 0, my_checksum, my_id, my_seq_number)

        pad_bytes = []
        start_val = 0x42

        if sys.version[:1] == '2':
            bytes_count = struct.calcsize("d")
            data = ((PACKET_SIZE - 8) - bytes_count) * "Q"
            data = struct.pack("d", default_timer()) + data
        else:
            for i in range(start_val, start_val + (PACKET_SIZE - 8)):
                pad_bytes += [(i & 0xff)]
            data = bytearray(pad_bytes)

        send_time = default_timer()

        try:
            self.server_socket.sendto(data, (self.destination_ip, 1))  # Port number is irrelevant for ICMP
        except socket.error as e:
            print(f"General failure ({e.args[1]})")
            return

        return send_time
