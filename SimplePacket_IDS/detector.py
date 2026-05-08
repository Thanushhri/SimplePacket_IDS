scan_tracker = {}

alerted_ips = set()

ALERT_THRESHOLD = 5

def detect_port_scan(ip, port):

    if ip not in scan_tracker:

        scan_tracker[ip] = []

    scan_tracker[ip].append(port)

    unique_ports = set(scan_tracker[ip])

    if len(unique_ports) >= ALERT_THRESHOLD:

        if ip not in alerted_ips:

            alerted_ips.add(ip)

            return True

    return False