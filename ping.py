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
        self._id = os.getpid() & 0xFFFF

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

        sent_time = self.send_one_ping(sequence_count)

        if sent_time is None:
            self.server_socket.close()
            return delay

        return delay

    def send_one_ping(self, sequence_count):
        checksum_num = 0

        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum_num, self._id, sequence_count)

        pad_bytes = []
        start_val = 0x42

        if sys.version[:1] == '2':
            bytes_count = struct.calcsize("d")
            data = ((PACKET_SIZE - 8) - bytes_count) * "Q"
            data = struct.pack("d", default_timer()) + data
        else:
            for i in range(start_val, start_val + (PACKET_SIZE - 8)):
                pad_bytes += [(i & 0xff)]  # Keep chars in the 0-255 range
            # data = bytes(pad_bytes)
            data = bytearray(pad_bytes)

        checksum_num = self.checksum(header + data)

        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum_num, self._id, sequence_count)

        packet = header + data

        send_time = default_timer()

        try:
            self.server_socket.sendto(packet, (self.destination_ip, 1))
        except socket.error as e:
            print("General failure (%s)" % (e.args[1]))
            return

        return send_time

    def checksum(self, source_string):
        count_to = (int(len(source_string) / 2)) * 2
        summ = 0
        count = 0

        low_byte = 0
        high_byte = 0
        while count < count_to:
            if sys.byteorder == "little":
                low_byte = source_string[count]
                high_byte = source_string[count + 1]
            else:
                low_byte = source_string[count + 1]
                high_byte = source_string[count]

            summ = summ + (high_byte * 256 + low_byte)

            count += 2

        if count_to < len(source_string):
            low_byte = source_string[len(source_string) - 1]
            summ += low_byte

        summ &= 0xffffffff

        summ = (summ >> 16) + (summ & 0xffff)
        summ += (summ >> 16)
        answer = ~summ & 0xffff
        answer = socket.htons(answer)

        return answer
