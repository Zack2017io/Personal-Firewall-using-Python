import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import json
import threading

# Load firewall rules
with open("rules.json", "r") as f:
    rules = json.load(f)

blocked_ips = rules["blocked_ips"]
blocked_ports = rules["blocked_ports"]
allowed_protocols = [proto.upper() for proto in rules["allowed_protocols"]]

running = False  # Global flag to control sniffing

def log_to_gui(message):
    log_box.insert(tk.END, message + "\n")
    log_box.yview(tk.END)

def log_to_file(packet, action, reason="N/A"):
    with open("firewall_log.txt", "a") as log:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log.write(f"[{timestamp}] {action}: {packet.summary()} | Reason: {reason}\n")

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src

        if ip_src in blocked_ips:
            msg = f"❌ Blocked IP: {ip_src}"
            log_to_gui(msg)
            log_to_file(packet, "Blocked", "Source IP")
            return

        if packet.haslayer(TCP) and packet[TCP].dport in blocked_ports:
            msg = f"❌ Blocked TCP Port: {packet[TCP].dport}"
            log_to_gui(msg)
            log_to_file(packet, "Blocked", "TCP Port")
            return

        if packet.haslayer(UDP) and packet[UDP].dport in blocked_ports:
            msg = f"❌ Blocked UDP Port: {packet[UDP].dport}"
            log_to_gui(msg)
            log_to_file(packet, "Blocked", "UDP Port")
            return

        msg = f"✅ Allowed: {packet.summary()}"
        log_to_gui(msg)
        log_to_file(packet, "Allowed", "Rule Passed")

def sniff_packets():
    sniff(prn=packet_callback, store=0, stop_filter=lambda x: not running)

def start_sniffing():
    global running
    if not running:
        running = True
        log_to_gui("▶️ Sniffing started...")
        thread = threading.Thread(target=sniff_packets)
        thread.daemon = True
        thread.start()

def stop_sniffing():
    global running
    running = False
    log_to_gui("⛔ Sniffing stopped.")

# Build GUI
window = tk.Tk()
window.title("Python Firewall")
window.geometry("700x500")

log_box = scrolledtext.ScrolledText(window, width=85, height=25, wrap=tk.WORD)
log_box.pack(pady=10)

btn_frame = tk.Frame(window)
btn_frame.pack()

start_btn = tk.Button(btn_frame, text="Start Sniffing", command=start_sniffing, bg="green", fg="white", width=15)
start_btn.pack(side=tk.LEFT, padx=10)

stop_btn = tk.Button(btn_frame, text="Stop Sniffing", command=stop_sniffing, bg="red", fg="white", width=15)
stop_btn.pack(side=tk.LEFT, padx=10)

def open_rule_editor():
    editor = tk.Toplevel(window)
    editor.title("Edit Firewall Rules")
    editor.geometry("400x300")

    # Current rules
    ip_label = tk.Label(editor, text="Blocked IPs (comma-separated):")
    ip_label.pack()
    ip_entry = tk.Entry(editor, width=50)
    ip_entry.insert(0, ",".join(blocked_ips))
    ip_entry.pack(pady=5)

    port_label = tk.Label(editor, text="Blocked Ports (comma-separated):")
    port_label.pack()
    port_entry = tk.Entry(editor, width=50)
    port_entry.insert(0, ",".join(map(str, blocked_ports)))
    port_entry.pack(pady=5)

    def save_rules():
        new_ips = ip_entry.get().split(",")
        new_ports = list(map(int, port_entry.get().split(",")))
        rules["blocked_ips"][:] = [ip.strip() for ip in new_ips if ip.strip()]
        rules["blocked_ports"][:] = new_ports
        with open("rules.json", "w") as f:
            json.dump(rules, f, indent=4)
        log_to_gui("✅ Rules updated successfully.")
        editor.destroy()

    save_btn = tk.Button(editor, text="Save Changes", command=save_rules, bg="blue", fg="white")
    save_btn.pack(pady=10)

rule_btn = tk.Button(btn_frame, text="Edit Rules", command=open_rule_editor, bg="orange", fg="black", width=15)
rule_btn.pack(side=tk.LEFT, padx=10)

window.mainloop()
