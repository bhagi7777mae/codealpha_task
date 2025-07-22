from scapy.all import sniff, IP, TCP, ICMP
from collections import defaultdict
import time

# Tracking connection attempts
port_scan_tracker = defaultdict(list)
ICMP_tracker = defaultdict(int)

# Detection thresholds
PORT_SCAN_THRESHOLD = 10  # connections in 5 seconds
ICMP_THRESHOLD = 20       # pings in 10 seconds

def detect_intrusion(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Detect TCP Port Scans
        if TCP in packet:
            dport = packet[TCP].dport
            current_time = time.time()
            port_scan_tracker[ip_src].append((dport, current_time))

            # Keep only recent attempts
            port_scan_tracker[ip_src] = [(port, t) for port, t in port_scan_tracker[ip_src] if current_time - t < 5]
            if len(set([port for port, _ in port_scan_tracker[ip_src]])) > PORT_SCAN_THRESHOLD:
                print(f"[!] Possible Port Scan from {ip_src} targeting {ip_dst}")
        
        # Detect ICMP Floods
        if ICMP in packet:
            ICMP_tracker[ip_src] += 1
            if ICMP_tracker[ip_src] > ICMP_THRESHOLD:
                print(f"[!] Possible ICMP Flood Attack from {ip_src} to {ip_dst}")
                ICMP_tracker[ip_src] = 0  # reset to prevent repeated alerts

# Start sniffing
print("NIDS is running... Press Ctrl+C to stop.")
sniff(filter="ip", prn=detect_intrusion, store=0)
