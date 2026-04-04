# 🛡️ Smart College Cyber Security & Infrastructure Management System (SCCSIMS)

A lightweight yet powerful **LAN Monitoring & Cybersecurity Platform** designed to detect unauthorized devices, monitor system activity, and provide administrators with **real-time network visibility**.

> 🚀 Built as a final-year project demonstrating practical implementation of **cybersecurity, network monitoring, and SOC-style systems**.

---

## 📸 Project Preview

|  **Login page**  |  **Dashboard**  |
|:----------------:|:---------------:|
|<img width="1916" height="883" alt="Screenshot 2026-04-04 214130" src="https://github.com/user-attachments/assets/595694b2-a651-44d8-82ee-fd22f88a96a3" />|<img width="952" height="427" alt="image" src="https://github.com/user-attachments/assets/7059990e-5c5c-4446-b629-7bb23ee0ebb3" />|
|  **Scan Port**   | **Logs Viewer** |
|<img width="1162" height="732" alt="image" src="https://github.com/user-attachments/assets/c9ebb7ba-1cc0-4371-89b6-be1a157b9ce8" />|<img width="1382" height="768" alt="image" src="https://github.com/user-attachments/assets/d2ea4443-a251-4a0d-b500-0fd5ba152749" />|

---

## 🚀 Key Features

✔ Real-time device monitoring<br>
✔ LAN network discovery (ARP + Ping scanning)<br>
✔ Rogue / unauthorized device detection<br>
✔ Duplicate IP & spoofing detection<br>
✔ Trusted device approval system<br>
✔ Live SOC-style dashboard<br>
✔ Port scanning with risk classification<br>
✔ PDF security report generation<br>
✔ CPU & RAM monitoring of client systems<br>
✔ Scan history logging (SQLite)<br>

---

## 🧠 System Architecture

```
Client Agent (agent.py)
        │
        │ Sends system data every 10 seconds
        ▼
Flask Server (app.py)
        │
        ├── Device Monitoring API
        ├── Logging & Activity Monitoring
        ├── Network Scanner (ARP + Ping)
        ├── Rogue Device Detection
        ├── Device Authorization Management (Approve / Disapprove)
        ├── Port Scanner Module
        ├── Report Generator (PDF)
        └── Admin Dashboard (Web Interface)
        │
        ▼

SQLite Database (sccsims.db)
```

---

## 🛠️ Tech Stack

| Component          | Technology                         |
|--------------------|------------------------------------|
| Backend            | Python                             |
| Web Framework      | Flask                              |
| Database           | SQLite                             |
| Network Scanning   | Scapy, Socket                      |
| Concurrency        | Multithreading(ThreadPoolExecutor) |
| Data Visualization | Matplotilib, NumPy                 |
| System Monitoring  | psutil                             |
| Frontend           | HTML, CSS, JavaScript              |
| Reporting          | ReportLab                          |
| Security           | Werkzeug (Password Hashing)        |

---

## 📜 Logging & Monitoring

* Implemented using Python’s built-in **logging module**
* Tracks:

  * Server activity
  * Network scans
  * Threat detection events
  * Admin actions (approve/disapprove)
* Logs stored in: `sccsims.log`

## ⚙️ Installation & Setup

### 1️⃣ Clone Repository

```bash
git clone https://github.com/ByteBandit-100/SCCSIMS.git
cd SCCSIMS
```

---

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---
### 3️⃣ Update /server/arp_scanner.py

```
INTERFACE = [your_system_working_interface_id] 
OR 
INTERFACE = None   #BY DEFAULT
```

###  4️⃣ ⃣ Run Server

```bash
python app.py
```

🌐 Access Dashboard:

```
http://localhost:5000
```

---

## 🔐 Default Credentials

```
Username: admin
Password: admin123
```

⚠️ *Change credentials before production use.*

---

## 🖥️ Running the Monitoring Agent

On each client machine:

### 1. Update Server IP in `agent.py`

```python
SERVER_URL = "http://SERVER_IP:5000/api/device"
```

---

### 2. Run Agent

```bash
python agent.py
```

📡 Device sends system data every *2 seconds**

---

## 📊 Features Breakdown

### 🔍 Network Monitoring

* Detects all devices in LAN
* Tracks IP, MAC, hostname
* Real-time updates

---

### 🚨 Threat Detection

* Rogue device detection
* Duplicate IP detection
* Unauthorized access alerts

---

### 🔎 Port Scanner

* Multi-threaded scanning
* Risk classification (LOW / HIGH)
* Live scan updates

---

### 📄 Report Generation

* Professional PDF reports
* Risk highlighting (RED for HIGH)
* Summary + recommendations

---

## 🛡️ Security Concepts Demonstrated

* Network Discovery
* Device Fingerprinting
* Rogue Device Detection
* Port Vulnerability Analysis
* Real-Time Monitoring
* Basic SOC (Security Operations Center) Design

---

## 🎯 Unique Highlights

🔥 SOC-style dashboard (rare in student projects)<br>
🔥 Terminal + Web hybrid monitoring<br>
🔥 Real-time threat detection<br>
🔥 Automated PDF reporting system<br>

---

## ⚠️ Limitations

* Works only in LAN environment
* No advanced IDS (Snort/Suricata level)
* No encrypted communication between agent & server
* Basic authentication system

---

## 🚀 Future Enhancements

* Intrusion Detection System (IDS)
* ARP spoofing protection
* WebSocket real-time updates
* Role-based authentication
* Network topology visualization
* Cloud deployment support

---

## 👨‍💻 Author

**Mohit (ByteBandit-100)**

---

## ⭐ Contribution

Feel free to fork, improve, and submit pull requests!

---

## 📜 License

This project is for educational purposes.

---

## 💡 Final Note

> This project demonstrates how cybersecurity concepts can be implemented in a **real-world mini SOC system**, making it highly suitable for academic and practical learning.

---
