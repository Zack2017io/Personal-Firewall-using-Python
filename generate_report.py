from datetime import datetime

def generate_html_report(log_file="firewall_log.txt", output_file="report.html"):
    with open(log_file, "r") as f:
        lines = f.readlines()

    html = """
    <html>
    <head>
        <title>Firewall Log Report</title>
        <style>
            body {{ font-family: Arial; margin: 20px; }}
            h1 {{ color: #333; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 10px; border: 1px solid #ccc; text-align: left; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
        </style>
    </head>
    <body>
        <h1>Firewall Log Report</h1>
        <p>Generated: {}</p>
        <table>
            <tr><th>Time</th><th>Action</th><th>Details</th><th>Reason</th></tr>
""".format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    for line in lines:
        if "]" in line:
            time_part = line.split("]")[0][1:]
            rest = line.split("]")[1].strip().split(" | ")
            action, details = rest[0].split(":", 1)
            reason = rest[1].split(":")[1] if len(rest) > 1 else "N/A"
            html += f"<tr><td>{time_part}</td><td>{action.strip()}</td><td>{details.strip()}</td><td>{reason.strip()}</td></tr>\n"

    html += "</table></body></html>"

    with open(output_file, "w") as f:
        f.write(html)

    print("✅ Report generated as 'report.html'.")

# Run
generate_html_report()
