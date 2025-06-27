Personal Firewall using Python
📌 Overview
This project implements a lightweight personal firewall in Python that passively monitors network traffic, applies rule-based filtering, logs events, 
and presents a graphical user interface (GUI) for user interaction. It was developed as part of a cybersecurity internship to gain hands-on experience in network monitoring, security policy enforcement, and threat visibility.

🛠️ Features Implemented
Live Packet Sniffing using Scapy

Rule-Based Filtering of packets based on IPs, ports, and protocols

JSON-based Rule Management to allow easy updates

Tkinter GUI to start/stop monitoring and view logs live

Interactive Rule Editor from within the GUI

HTML Report Generator to review and summarize logs visually

⚙️ Tools & Technologies Used
Python 3.x

Scapy: For capturing and parsing packets

Tkinter: For building the user interface

JSON: Used to configure firewall rules

HTML/CSS: For generating log summary reports

Windows 10/11: Primary development environment

📂 Project Structure
firewall_project/
│
├── firewall.py         # CLI version (Stage 2)
├── gui.py                  # GUI version (Stage 4+)
├── rules.json              # Custom rules for filtering
├── firewall_log.txt        # Logged activity
├── generate_report.py      # Creates a report.html from logs
├── report.html             # Final report output
└── README.md               # This file

✅ Project Development Stages
Stage 1: Packet Sniffing
Used Scapy to capture live packets and print summaries in the terminal.

Focused on understanding packet layers (Ether/IP/TCP/UDP).

Stage 2: Filtering Rules
Introduced rule logic to allow/block packets based on:

Source IP addresses

Destination ports

Protocols (TCP/UDP)

Logged each decision with a reason to firewall_log.txt.

Stage 3: Rule Management & Logging
Moved rules to an external rules.json file for easier updates.

Improved log format with timestamps, action (allowed/blocked), and summary.

Stage 4: GUI Interface
Developed a simple Tkinter interface:

Start and stop sniffing

View real-time logs

Styled with buttons and a scrollable text box

Stage 5: GUI Rule Manager
Integrated a rule editor window inside the GUI:

Modify blocked IPs and ports

Save changes directly to rules.json

No manual editing needed

Stage 6: HTML Report Generator
Wrote a script (generate_report.py) to:

Parse logs and generate report.html

Structure it in a readable table format with color coding

Useful for documentation and analysis

📊 How to Use
1. Start GUI:
    -> python gui.py
2. Start/Stop Monitoring using the interface.
3. Edit Rules by clicking the “Edit Rules” button.
4. Generate Report (optional):
    -> python generate_report.py

 🧠 Key Learnings
How to inspect and interpret live network traffic

Building real-time loggers and analyzers

Creating user-friendly security tools with GUIs

Converting raw logs into visual reports

Managing JSON-based rule systems

Understanding basic concepts in firewall logic

🚀 Conclusion
The Personal Firewall project helped bridge theoretical cybersecurity concepts with practical, real-world implementation.
It serves as a foundational tool for understanding traffic filtering, protocol analysis, and rule-based security design using Python.  

