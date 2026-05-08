# SimplePacketIDS

A Python-based Intrusion Detection System (IDS) with real-time packet sniffing, port scan detection, alert logging, and a live GUI dashboard.

---

# Features

- Real-time packet sniffing
- TCP/IP traffic monitoring
- Port scan detection
- Live cybersecurity dashboard
- Alert logging system
- Packet counter
- Alert counter
- Start/Stop IDS controls
- Real-time traffic monitoring

---

# Technologies Used

- Python
- Scapy
- Tkinter
- Npcap
- VS Code

---

# Project Architecture

```text
Network Traffic
        ↓
Packet Sniffer
        ↓
Traffic Analyzer
        ↓
Attack Detection
        ↓
GUI Dashboard
        ↓
Alert Logging
```

---

# Dashboard Preview

Add your screenshot inside:

```text
screenshots/dashboard.png
```

Then GitHub will automatically display it.

```markdown
![Dashboard](screenshots/dashboard.png)
```

---

# Installation

## 1. Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/SimplePacketIDS.git
```

---

## 2. Open Project Folder

```bash
cd SimplePacketIDS
```

---

## 3. Install Requirements

```bash
pip install -r requirements.txt
```

---

## 4. Run Dashboard

```bash
python dashboard.py
```

---

# How It Works

The IDS captures network packets using Scapy and analyzes TCP/IP traffic in real time.

The system detects suspicious behavior such as:

- Port scanning
- Repeated connection attempts
- Suspicious TCP traffic

Detected attacks generate:

- Real-time alerts
- Alert counter updates
- Log file entries

---

# Files Structure

```text
SimplePacketIDS/
│
├── dashboard.py
├── detector.py
├── logger.py
├── scan_test.py
├── sniffer.py
├── requirements.txt
├── README.md
├── alerts.log
│
├── screenshots/
│   └── dashboard.png
│
└── .venv/
```

---

# Example Alert

```text
!!! SECURITY ALERT !!!
Possible Port Scan Detected
Attacker IP: 192.168.x.x
```

---

# Future Improvements

- Wi-Fi attack detection
- Deauthentication attack detection
- Machine learning-based anomaly detection
- Live traffic graphs
- Geolocation tracking
- PDF report generation
- Dark cyberpunk dashboard UI

---

# Educational Purpose

This project was built for:

- cybersecurity learning
- packet analysis practice
- intrusion detection concepts
- networking visualization
- security monitoring research

---

# Author

Thanushhri M

GitHub:
https://github.com/ThanushhriM

---

# License

This project is for educational and research purposes only.
