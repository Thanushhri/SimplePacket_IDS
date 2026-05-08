import socket

target = "192.168.1.1"

print("Starting simulated port scan...")

for port in range(1, 50):

    try:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.settimeout(0.05)

        result = s.connect_ex((target, port))

        print(f"Scanned Port: {port}")

        s.close()

    except:

        pass

print("Scan complete.")