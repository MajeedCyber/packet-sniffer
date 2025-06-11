# Network Packet Sniffer & Analyzer

A Python-based network packet sniffer that monitors traffic and detects suspicious activity using Scapy.

## Features

- Captures IP, TCP, and UDP packets in real-time
- Detects traffic involving known malicious IPs
- Identifies suspicious port activity (like C2 communication ports)
- Logs all network activity with timestamps
- Lightweight and easy to customize

## Demo

### Running the Sniffer
![Running the sniffer](screenshots/running.png)
*The sniffer starting up and waiting for network traffic*

### Normal Traffic Detection
![Normal traffic](screenshots/normal_traffic.png)
*Example of normal HTTP traffic being logged*

### Malicious IP Detection
![Malicious IP detection](screenshots/malicious_ip.png)
*Alert when traffic matches known malicious IP addresses*

### Suspicious Port Detection
![Suspicious port](screenshots/suspicious_port.png)
*Warning when traffic uses known suspicious ports (like 4444)*

### Log File Output
![Log file](screenshots/log_file.png)
*Example of the generated log file with timestamps*

## How to Create These Screenshots

1. **Setup Screenshot**: Run the script in your terminal and capture the startup message
   ```bash
   python packet_sniffer.py
