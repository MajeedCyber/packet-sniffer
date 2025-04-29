from scapy.all import sniff, IP, TCP, UDP
import datetime
import sys

# List of known malicious IPs (for demonstration; replace with a real threat intelligence feed)
MALICIOUS_IPS = ["203.0.113.5", "198.51.100.10"]  # Example IPs (RFC 5737 reserved IPs)

# Log file to store packet details
LOG_FILE = "network_traffic.log"

def log_packet(packet_info, suspicious=False):
    """Log packet details to a file with a timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {packet_info}"
    if suspicious:
        log_entry += " [SUSPICIOUS]"
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")
    print(log_entry)

def check_suspicious(packet):
    """Check if the packet matches any suspicious criteria."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Rule 1: Check if source or destination IP is in the malicious list
        if src_ip in MALICIOUS_IPS or dst_ip in MALICIOUS_IPS:
            return True, f"Traffic involving known malicious IP: {src_ip} -> {dst_ip}"
        
        # Rule 2: Example rule for excessive connections (simplified; could track frequency)
        # For this demo, flag any traffic to a specific port (e.g., 4444, often used for C2)
        if TCP in packet and packet[TCP].dport == 4444:
            return True, f"Suspicious port detected: {packet[TCP].dport} (potential C2 communication)"
    
    return False, ""

def packet_callback(packet):
    """Process each captured packet and log relevant details."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        proto_name = "Unknown"
        
        # Determine the protocol and port (if applicable)
        if protocol == 6 and TCP in packet:  # TCP
            proto_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif protocol == 17 and UDP in packet:  # UDP
            proto_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port = dst_port = "N/A"
        
        # Format packet info
        packet_info = f"Protocol: {proto_name} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        
        # Check for suspicious activity
        is_suspicious, reason = check_suspicious(packet)
        if is_suspicious:
            packet_info += f" | Reason: {reason}"
        
        # Log the packet
        log_packet(packet_info, suspicious=is_suspicious)

def main():
    """Main function to start the packet sniffer."""
    print(f"[*] Starting packet sniffer... Logs will be saved to {LOG_FILE}")
    print("[*] Press Ctrl+C to stop sniffing.")
    
    try:
        # Sniff packets on the default interface (modify 'iface' if needed)
        # Filter for IP packets to reduce noise (modify filter as needed)
        sniff(filter="ip", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[*] Packet sniffing stopped by user.")
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
