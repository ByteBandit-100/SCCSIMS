# Generate a complete professional project synopsis PDF for the user using reportlab

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib import colors

file_path = "/mnt/data/SCCSIMS_Full_Project_Synopsis.pdf"

styles = getSampleStyleSheet()

title = ParagraphStyle("title", parent=styles["Title"], alignment=1, spaceAfter=20)
heading = ParagraphStyle("heading", parent=styles["Heading2"], spaceBefore=14, spaceAfter=6)
text = ParagraphStyle("text", parent=styles["BodyText"], leading=16)

story = []

# Cover Page
story.append(Paragraph("BACHELOR OF COMPUTER APPLICATIONS (BCA)", title))
story.append(Paragraph("FINAL YEAR PROJECT SYNOPSIS", styles["Heading2"]))
story.append(Spacer(1,20))
story.append(Paragraph("Smart College Cyber Security & Infrastructure Management System (SCCSIMS)", styles["Heading1"]))
story.append(Spacer(1,40))

info_table = Table([
["Student Name","Mohit Gautam"],
["Course","Bachelor of Computer Applications (BCA)"],
["Project Type","Final Year Major Project"],
["Technology","Python, Flask, SQLite"],
["Domain","Cyber Security / Network Monitoring"]
], colWidths=[2.5*inch,4*inch])

info_table.setStyle(TableStyle([
("GRID",(0,0),(-1,-1),0.5,colors.grey),
("BACKGROUND",(0,0),(0,-1),colors.lightgrey)
]))

story.append(info_table)
story.append(PageBreak())

# Abstract
story.append(Paragraph("1. Abstract", heading))
story.append(Paragraph("""
The Smart College Cyber Security & Infrastructure Management System (SCCSIMS) is a network monitoring and
security solution designed for educational institutions. Modern colleges operate large networks consisting
of laboratories, faculty systems, and administrative computers. Monitoring these systems manually is
inefficient and increases the risk of security issues.

This project introduces a centralized monitoring platform where computers running a lightweight Python
agent continuously send system information to a central monitoring server. The server collects information
such as CPU usage, RAM usage, operating system, hostname, and IP address and stores it in a database.
A web dashboard allows administrators to monitor device status in real time.

Additionally, the system includes a network discovery module that scans the local network to detect active
devices. This allows administrators to identify unknown or unauthorized devices connected to the network.
""", text))

# Introduction
story.append(Paragraph("2. Introduction", heading))
story.append(Paragraph("""
Computer networks are essential components of modern educational infrastructure. Colleges rely on
interconnected systems to manage academic resources, administrative operations, and student services.
However, as networks grow larger, monitoring and maintaining the infrastructure becomes increasingly
difficult.

The Smart College Cyber Security & Infrastructure Management System provides a lightweight monitoring
solution that enables administrators to track device status and system performance using a centralized
dashboard. This helps improve visibility, management, and cybersecurity awareness across the network.
""", text))

# Problem Statement
story.append(Paragraph("3. Problem Statement", heading))
story.append(Paragraph("""
Many college laboratories lack proper network monitoring tools. Administrators often cannot determine
which systems are active, which machines are consuming excessive resources, or whether unauthorized
devices are connected to the network. This lack of visibility creates security vulnerabilities and
reduces network efficiency.

Therefore, a centralized monitoring system is required to track devices, monitor system performance,
and detect new devices connected to the network.
""", text))

# Objectives
story.append(Paragraph("4. Objectives", heading))
objectives=[
"Develop a centralized system for monitoring computers within a campus network.",
"Collect system information such as CPU usage, RAM usage, operating system, hostname, and IP address.",
"Display device status (online/offline) using a real-time dashboard.",
"Detect devices connected to the local network through network scanning.",
"Identify unknown or unauthorized devices within the network.",
"Improve infrastructure monitoring and cybersecurity awareness."
]

for o in objectives:
    story.append(Paragraph(f"• {o}", text))

# Scope
story.append(Paragraph("5. Scope of the Project", heading))
story.append(Paragraph("""
The system is designed primarily for college computer laboratories and small campus networks.
It can be used by network administrators to monitor systems in real time and detect active devices
within the network. The project focuses on LAN-based monitoring and does not require expensive
enterprise monitoring tools.

The system can also be adapted for use in small organizations, training centers, or educational labs.
""", text))

# Architecture
story.append(Paragraph("6. System Architecture", heading))
arch_table=Table([
["Component","Description"],
["Client Agent","Collects system information and sends it to the monitoring server."],
["Flask Monitoring Server","Receives data through API endpoints and processes the information."],
["SQLite Database","Stores system data and device information."],
["Web Dashboard","Displays monitoring results for administrators."],
["Network Scanner","Detects active devices within the LAN."]
], colWidths=[2.5*inch,4*inch])

arch_table.setStyle(TableStyle([
("BACKGROUND",(0,0),(-1,0),colors.lightgrey),
("GRID",(0,0),(-1,-1),0.5,colors.grey)
]))

story.append(arch_table)

# Methodology
story.append(Paragraph("7. Methodology / Working", heading))
story.append(Paragraph("""
The system follows a client-server architecture. Each computer runs a Python-based monitoring agent
that collects system statistics. The agent sends data to the Flask monitoring server through an API.

The server processes incoming data and stores it in the SQLite database. The monitoring dashboard
retrieves this information and displays device details such as hostname, IP address, CPU usage,
RAM usage, and status.

A separate network scanning module periodically scans the network to detect active devices.
""", text))

# Technologies
story.append(Paragraph("8. Technologies Used", heading))
tech=[
"Python – Core programming language",
"Flask – Web framework for server and API",
"SQLite – Database for storing monitoring data",
"HTML & CSS – Dashboard interface",
"psutil Library – Collect CPU and RAM usage",
"Socket & Platform Libraries – System information collection"
]

for t in tech:
    story.append(Paragraph(f"• {t}", text))

# Advantages
story.append(Paragraph("9. Advantages", heading))
advantages=[
"Real-time monitoring of systems",
"Centralized infrastructure management",
"Detection of active devices in the network",
"Lightweight and easy to deploy",
"Low cost monitoring solution"
]

for a in advantages:
    story.append(Paragraph(f"• {a}", text))

# Limitations
story.append(Paragraph("10. Limitations", heading))
story.append(Paragraph("""
The system currently works within a local network environment and relies on basic ping-based
device detection. It does not perform deep packet inspection or advanced intrusion detection.
However, the system provides a strong foundation for further cybersecurity features.
""", text))

# Future Scope
story.append(Paragraph("11. Future Scope", heading))
story.append(Paragraph("""
Future improvements may include intrusion detection features, graphical network visualization,
automated alerts for suspicious activity, cloud-based monitoring, and machine learning algorithms
for detecting abnormal network behavior.
""", text))

# Conclusion
story.append(Paragraph("12. Conclusion", heading))
story.append(Paragraph("""
The Smart College Cyber Security & Infrastructure Management System provides a practical
solution for monitoring campus networks. By combining system monitoring, device discovery,
and centralized management, the project demonstrates how modern software tools can improve
network administration and cybersecurity awareness in educational environments.
""", text))

doc=SimpleDocTemplate(file_path,pagesize=A4)
doc.build(story)

print(file_path)