# Init python ping project
from ping import Ping

hostname = input("Enter hostname: ")
packet_number = int(input("Enter packet number: "))
packet_size = int(input("Enter packet size: (like 64/32) "))

ping = Ping(packet_num=packet_number, hostname=hostname, packet_size=packet_size)
ping.calculate_ping()
