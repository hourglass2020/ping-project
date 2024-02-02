import socket
import struct
import sys
import time
import os

import select

ICMP_MODE = socket.getprotobyname("icmp")
WAIT_TIMEOUT = 3000.0
MAX_SLEEP = 1000

ICMP_ECHO_REPLY = 0
ICMP_ECHO = 8
ICMP_MAX_RECV = 2048


class Ping:
    def __init__(self, packet_num, hostname, packet_size):
        self.destination_ip = None
        self.server_socket = None
        self.packet_size = packet_size
        self.packet_num = packet_num
        self.hostname = hostname
        self._id = os.getpid() & 0xFFFF

    def create_socket(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_MODE)
        except socket.error as e:
            print(f"An error ocurred: {e.args[1]})")
            raise

    def calculate_ping(self):
        try:
            self.destination_ip = socket.gethostbyname(self.hostname)
            print(f"\nPing {self.hostname}")
            print(f"Destination IP: {self.destination_ip}")
            print(f"Packet size: {self.packet_size}\n\n")
        except socket.gaierror as e:
            print(f"\nError: Unknown host: {self.hostname} ({e.args[1]})")
            return

        for index in range(self.packet_num):
            delay = self.get_ping(index)

            if delay is None:
                delay = 0

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

    def create_packet(self, sequence_count):
        checksum_num = 0

        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum_num, self._id, sequence_count)

        pad_bytes = []
        start_val = 0x42

        if sys.version[:1] == '2':
            bytes_count = struct.calcsize("d")
            data = ((self.packet_size - 8) - bytes_count) * "Q"
            data = struct.pack("d", time.time()) + data
        else:
            for i in range(start_val, start_val + (self.packet_size - 8)):
                pad_bytes += [(i & 0xff)]
            data = bytearray(pad_bytes)

        checksum_num = self.checksum(header + data)

        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum_num, self._id, sequence_count)

        packet = header + data
        return packet

    def send_packet(self, sequence_count):
        send_time = time.time()

        try:
            self.server_socket.sendto(self.create_packet(sequence_count), (self.destination_ip, 1))
        except socket.error as e:
            print(f"An error occurred: ({e.args[1]})")
            return

        return send_time

    def receive_packet(self):

        time_left = WAIT_TIMEOUT / 1000

        while True:
            start_timer = time.time()
            duration = (time.time() - start_timer)
            ready = select.select([self.server_socket], [], [], time_left)

            if not ready[0]:
                return None, 0, 0, 0, 0

            time_received = time.time()

            rec_packet, addr = self.server_socket.recvfrom(ICMP_MAX_RECV)

            icmp_header = rec_packet[20:28]
            icmp_packet = struct.unpack("!BBHHH", icmp_header)

            if icmp_packet[3] == self._id:  # Our packet
                return time_received

            time_left = time_left - duration
            if time_left <= 0:
                return None, 0, 0, 0, 0

    def checksum(self, data):
        count_to = (int(len(data) / 2)) * 2
        summ = 0
        count = 0

        low_b = 0
        high_b = 0
        while count < count_to:
            if sys.byteorder == "little":
                low_b = data[count]
                high_b = data[count + 1]
            else:
                low_b = data[count + 1]
                high_b = data[count]

            summ = summ + (high_b * 256 + low_b)

            count += 2

        if count_to < len(data):
            low_b = data[len(data) - 1]
            summ += low_b

        summ &= 0xffffffff

        summ = (summ >> 16) + (summ & 0xffff)
        summ += (summ >> 16)
        answer = ~summ & 0xffff
        answer = socket.htons(answer)

        return answer
