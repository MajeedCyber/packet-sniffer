# Network Packet Sniffer with Suspicious Activity Detection

A Python-based packet sniffer that monitors network traffic, logs packet details, and detects suspicious activity based on predefined rules.

## Features

- Captures and logs IP, TCP, and UDP packets
- Detects traffic involving known malicious IP addresses
- Flags suspicious port activity (e.g., port 4444 often used for C2 communication)
- Logs all network traffic with timestamps
- Highlights suspicious activity in logs

## Requirements

- Python 3.x
- Scapy library
- Administrator/root privileges (for packet capture)

