# Smart College Cyber Security & Infrastructure Management System (SCCSIMS)

A lightweight **LAN monitoring and cybersecurity platform** that detects unauthorized devices, monitors system activity, and provides administrators with real-time network visibility.

Built using **Python, Flask, Scapy, and SQLite**, SCCSIMS demonstrates practical implementation of network monitoring and cyber defense techniques in small institutional networks such as **college labs and classrooms**.

---

## Key Capabilities

• Real-time device monitoring  
• LAN network discovery (Ping + ARP scanning)  
• Rogue / unauthorized device detection  
• Trusted device approval system  
• Interactive web-based monitoring dashboard  
• CPU and RAM usage monitoring of client systems

---

## System Architecture
Agent (Client Devices)<br>
│<br>
│ Sends system data every 10 seconds<br>
▼<br>
Flask Server (app.py)<br>
│<br>
├── Device Monitoring API<br>
├── Network Scanner<br>
├── Rogue Device Detection<br>
└── Trusted Device Management<br>
│<br>
▼<br>
SQLite Database (sccsims.db)


---

## Technology Stack

| Component | Technology |
|--------|--------|
Backend | Python |
Web Framework | Flask |
Database | SQLite |
Network Scanning | Scapy |
System Monitoring | psutil |
Frontend | HTML, CSS, JavaScript |

---


## Installation

### 1. Clone the repository
git clone https://github.com/ByteBandit-100/SCCSIMS.git
cd SCCSIMS


### 2. Install dependencies


pip install flask scapy psutil requests


### 3. Run the server


python app.py


The dashboard will be available at:
http://localhost:5000
---

## Running the Monitoring Agent

On each client device:

1. Update the server IP in **agent.py**


SERVER_URL = "http://SERVER_IP:5000/api/device"


2. Run the agent <br>
python agent.py

The device will start sending system data every **10 seconds**.

---

## Database

The system uses **SQLite** and automatically creates the following tables:

### devices

Stores monitored client devices.

| Column | Description |
|------|------|
id | Primary key |
hostname | Device name |
ip_address | Device IP |
os | Operating system |
cpu_usage | CPU usage |
ram_usage | RAM usage |
location | Device location |
last_seen | Last activity timestamp |

### trusted_devices

Stores approved network devices.

| Column | Description |
|------|------|
id | Primary key |
ip_address | Trusted device IP |
mac_address | Device MAC |
device_name | Device name |
location | Network location |

---

## Security Concepts Demonstrated

- Network discovery
- Device fingerprinting
- Rogue device detection
- Trusted device management
- Real-time system monitoring

---

## Future Improvements

Possible extensions for the system include:

- Intrusion Detection System (IDS)
- ARP spoofing detection
- Network topology visualization
- Authentication for admin dashboard
- Real-time WebSocket dashboard updates

---

## Author

Mohit  
