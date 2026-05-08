from scapy.all import *
from detector import detect_port_scan
from logger import log_alert
from colorama import Fore, Style, init

init()

packet_count = 0
alert_count = 0

def process_packet(packet):

    global packet_count
    global alert_count

    packet_count += 1

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        print(Fore.CYAN + "\n========== PACKET ==========")

        print(Fore.YELLOW + f"Packet Number : {packet_count}")

        print(Fore.GREEN + f"Source IP      : {src_ip}")
        print(Fore.GREEN + f"Destination IP : {dst_ip}")

        # TCP Packets
        if packet.haslayer(TCP):

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            print(Fore.MAGENTA + "Protocol       : TCP")
            print(Fore.WHITE + f"Source Port    : {src_port}")
            print(Fore.WHITE + f"Destination Port: {dst_port}")

            # Detect Port Scan
            if detect_port_scan(src_ip, dst_port):

                alert_count += 1

                alert = f"Possible Port Scan Detected from {src_ip}"

                print(Fore.RED + "\n!!! SECURITY ALERT !!!")
                print(Fore.RED + alert)

                log_alert(alert)

        # UDP Packets
        elif packet.haslayer(UDP):

            print(Fore.MAGENTA + "Protocol       : UDP")

        # ICMP Packets
        elif packet.haslayer(ICMP):

            print(Fore.MAGENTA + "Protocol       : ICMP")

        print(Fore.CYAN + "============================")

        print(Fore.BLUE + f"Total Packets : {packet_count}")
        print(Fore.RED + f"Total Alerts  : {alert_count}")

        print(Style.RESET_ALL)

print(Fore.GREEN + "======================================")
print(Fore.GREEN + "      SimplePacketIDS Started")
print(Fore.GREEN + "======================================")

sniff(
    filter="ip",
    prn=process_packet,
    store=False
)