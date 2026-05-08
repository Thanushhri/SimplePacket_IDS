from tkinter import *
from tkinter.scrolledtext import ScrolledText
from scapy.all import *
from detector import detect_port_scan
from logger import log_alert
from datetime import datetime
import threading

# Global Variables
packet_count = 0
alert_count = 0
running = False

# -----------------------------
# CREATE MAIN WINDOW
# -----------------------------
root = Tk()

root.title("SimplePacketIDS Dashboard")

root.geometry("1000x700")

root.config(bg="black")

# -----------------------------
# TITLE
# -----------------------------
title = Label(
    root,
    text="SimplePacketIDS Dashboard",
    font=("Arial", 24, "bold"),
    fg="lime",
    bg="black"
)

title.pack(pady=10)

# -----------------------------
# PACKET COUNTER
# -----------------------------
packet_label = Label(
    root,
    text="Packets: 0",
    font=("Arial", 16),
    fg="cyan",
    bg="black"
)

packet_label.pack()

# -----------------------------
# ALERT COUNTER
# -----------------------------
alert_label = Label(
    root,
    text="Alerts: 0",
    font=("Arial", 16),
    fg="red",
    bg="black"
)

alert_label.pack()

# -----------------------------
# TRAFFIC DISPLAY WINDOW
# -----------------------------
traffic_box = ScrolledText(
    root,
    width=120,
    height=30,
    bg="black",
    fg="white",
    insertbackground="white",
    font=("Consolas", 10)
)

traffic_box.pack(pady=10)

# Text Colors
traffic_box.tag_config(
    "alert",
    foreground="red"
)

traffic_box.tag_config(
    "normal",
    foreground="white"
)

traffic_box.tag_config(
    "info",
    foreground="cyan"
)

# -----------------------------
# PROCESS PACKETS
# -----------------------------
def process_packet(packet):

    global packet_count
    global alert_count

    if not running:
        return

    if packet.haslayer(IP):

        packet_count += 1

        timestamp = datetime.now().strftime("%H:%M:%S")

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = "OTHER"

        src_port = "-"
        dst_port = "-"

        # TCP
        if packet.haslayer(TCP):

            protocol = "TCP"

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        # UDP
        elif packet.haslayer(UDP):

            protocol = "UDP"

        # ICMP
        elif packet.haslayer(ICMP):

            protocol = "ICMP"

        # Display Packet Info
        packet_info = (
            f"\n[{timestamp}] Packet #{packet_count}\n"
            f"Source IP       : {src_ip}\n"
            f"Destination IP  : {dst_ip}\n"
            f"Protocol        : {protocol}\n"
            f"Source Port     : {src_port}\n"
            f"Destination Port: {dst_port}\n"
            f"===============================\n"
        )

        traffic_box.insert(
            END,
            packet_info,
            "normal"
        )

        traffic_box.see(END)

        # Update Packet Counter
        packet_label.config(
            text=f"Packets: {packet_count}"
        )

        # Detect Port Scan
        if protocol == "TCP":

            if detect_port_scan(src_ip, dst_port):

                alert_count += 1

                alert_message = (
                    f"\n!!! SECURITY ALERT !!!\n"
                    f"Possible Port Scan Detected\n"
                    f"Attacker IP: {src_ip}\n"
                    f"Time: {timestamp}\n"
                    f"!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
                )

                traffic_box.insert(
                    END,
                    alert_message,
                    "alert"
                )

                traffic_box.see(END)

                # Update Alert Counter
                alert_label.config(
                    text=f"Alerts: {alert_count}"
                )

                # Save Alert
                log_alert(alert_message)

# -----------------------------
# START SNIFFING
# -----------------------------
def start_sniffing():

    sniff(
        filter="ip",
        prn=process_packet,
        store=False
    )

# -----------------------------
# START IDS
# -----------------------------
def start_ids():

    global running

    if not running:

        running = True

        thread = threading.Thread(
            target=start_sniffing
        )

        thread.daemon = True

        thread.start()

        traffic_box.insert(
            END,
            "\n[INFO] IDS Started...\n",
            "info"
        )

# -----------------------------
# STOP IDS
# -----------------------------
def stop_ids():

    global running

    running = False

    traffic_box.insert(
        END,
        "\n[INFO] IDS Stopped...\n",
        "info"
    )

# -----------------------------
# BUTTON FRAME
# -----------------------------
button_frame = Frame(
    root,
    bg="black"
)

button_frame.pack(pady=10)

# -----------------------------
# START BUTTON
# -----------------------------
start_button = Button(
    button_frame,
    text="Start IDS",
    command=start_ids,
    bg="green",
    fg="white",
    width=15,
    height=2,
    font=("Arial", 12, "bold")
)

start_button.grid(
    row=0,
    column=0,
    padx=20
)

# -----------------------------
# STOP BUTTON
# -----------------------------
stop_button = Button(
    button_frame,
    text="Stop IDS",
    command=stop_ids,
    bg="red",
    fg="white",
    width=15,
    height=2,
    font=("Arial", 12, "bold")
)

stop_button.grid(
    row=0,
    column=1,
    padx=20
)

# -----------------------------
# STATUS BAR
# -----------------------------
status_bar = Label(
    root,
    text="System Active",
    bg="black",
    fg="lime",
    font=("Arial", 10)
)

status_bar.pack(
    side=BOTTOM,
    fill=X
)

# -----------------------------
# RUN APPLICATION
# -----------------------------
root.mainloop()