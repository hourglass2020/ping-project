# Init python ping project
from ping import Ping

hostname = input("Enter hostname: ")
packet_number = int(input("Enter packet number: "))

ping = Ping(packet_num=packet_number, hostname=hostname)
ping.calculate_ping()
