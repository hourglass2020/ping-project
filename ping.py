import socket
import struct
import sys
import time
import os

import select

default_timer = time.time

ICMP_MODE = socket.getprotobyname("icmp")
PACKET_SIZE = 64
WAIT_TIMEOUT = 3000.0
MAX_SLEEP = 1000

ICMP_ECHO_REPLY = 0
ICMP_ECHO = 8
ICMP_MAX_RECV = 2048


class Ping:
    def __init__(self, packet_num, hostname):
        self.destination_ip = None
        self.server_socket = None

        self.packet_num = packet_num
        self.hostname = hostname
        self._id = os.getpid() & 0xFFFF

    def create_socket(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_MODE)
        except socket.error as e:
            print(f"failed. (socket error: {e.args[1]})")
            raise

    def calculate_ping(self):
        try:
            self.destination_ip = socket.gethostbyname(self.hostname)
            print(f"Ping {self.hostname}")
            print(f"Destination IP: {self.destination_ip}")
            print(f"Packet size: {PACKET_SIZE}\n\n")
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

        self.create_socket()
        sent_time = self.send_packet(sequence_count)

        if sent_time is None:
            self.server_socket.close()
            return delay

        recv_time = self.receive_packet()
        self.server_socket.close()

        if recv_time:
            delay = (recv_time - sent_time) * 1000
            print(f"Ping successful: time={round(delay, 2)}")

        else:
            delay = None
            print("Ping Timed out")

        return delay

    def send_packet(self, sequence_count):
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
                pad_bytes += [(i & 0xff)]
            data = bytearray(pad_bytes)

        checksum_num = self.checksum(header + data)

        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum_num, self._id, sequence_count)

        packet = header + data

        send_time = default_timer()

        try:
            self.server_socket.sendto(packet, (self.destination_ip, 1))
        except socket.error as e:
            print(f"General failure ({e.args[1]})")
            return

        return send_time

    def receive_packet(self):

        time_left = WAIT_TIMEOUT / 1000

        while True:
            started_select = default_timer()
            what_ready = select.select([self.server_socket], [], [], time_left)
            how_long_in_select = (default_timer() - started_select)

            if not what_ready[0]:  # Timeout
                return None, 0, 0, 0, 0

            time_received = default_timer()

            rec_packet, addr = self.server_socket.recvfrom(ICMP_MAX_RECV)

            icmp_header = rec_packet[20:28]
            icmp_packet = struct.unpack("!BBHHH", icmp_header)

            if icmp_packet[3] == self._id:  # Our packet
                return time_received

            time_left = time_left - how_long_in_select
            if time_left <= 0:
                return None, 0, 0, 0, 0

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
