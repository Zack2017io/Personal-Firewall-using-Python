import json
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

# 🔁 Load rules from JSON
with open("rules.json", "r") as f:
    rules = json.load(f)

blocked_ips = rules["blocked_ips"]
blocked_ports = rules["blocked_ports"]
allowed_protocols = [proto.upper() for proto in rules["allowed_protocols"]]

def log_packet(packet, action, reason="N/A"):
    with open("firewall_log.txt", "a") as log:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log.write(f"[{timestamp}] {action}: {packet.summary()} | Reason: {reason}\n")

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if ip_src in blocked_ips:
            print(f"Blocked IP: {ip_src}")
            log_packet(packet, "Blocked", "Source IP")
            return

        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            if dport in blocked_ports:
                print(f"Blocked Port: {dport}")
                log_packet(packet, "Blocked", "Blocked Port")
                return

        if packet.haslayer(UDP):
            dport = packet[UDP].dport
            if dport in blocked_ports:
                print(f"Blocked Port (UDP): {dport}")
                log_packet(packet, "Blocked", "Blocked Port")
                return

        # Log allowed traffic too (optional)
        print(f"✅ Allowed: {packet.summary()}")
        log_packet(packet, "Allowed", "Rule Passed")

# Start capturing
sniff(prn=packet_callback, store=0, count=50)

