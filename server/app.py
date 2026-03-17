from flask import Flask, request, jsonify, redirect
import sqlite3
import subprocess
from flask import render_template
from arp_scanner import scan_network_arp
from network_scanner import scan_network
from datetime import datetime

app = Flask(__name__)
DATABASE = "sccsims.db"

def get_mac_from_arp_cache(ip):

    try:
        output = subprocess.check_output("arp -a", shell=True).decode()

        for line in output.split("\n"):
            if ip in line:
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]

    except:
        pass

    return "Unknown"

@app.route("/")
def dashboard():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM devices")
    rows = cursor.fetchall()
    conn.close()

    devices = []
    current_time = datetime.now()

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT ip_address, mac_address FROM trusted_devices")
    trusted_rows = cursor.fetchall()

    trusted_ips = set([r[0] for r in trusted_rows])
    trusted_macs = set([r[1] for r in trusted_rows])

    trusted_devices = []

    for row in trusted_rows:
        trusted_devices.append({
            "ip": row[0],
            "mac": row[1]
        })


    conn.close()

    # build device list
    for row in rows:
        try:
            if row[8]:
                last_seen_time = datetime.strptime(str(row[8]), "%Y-%m-%d %H:%M:%S")
            else:
                last_seen_time = current_time
        except:
            last_seen_time = current_time

        time_diff = (current_time - last_seen_time).total_seconds()

        # ✅ FORCE numeric safety
        time_diff = float(time_diff)

        status = "ONLINE" if time_diff <= 30 else "OFFLINE"

        def safe_float(val):
            try:
                return float(val)
            except:
                return 0

        devices.append({
            "id": row[0],
            "hostname": row[1],
            "ip_address": row[2],
            "mac_address": row[3],
            "os": row[4],
            "cpu_usage": safe_float(row[5]),
            "ram_usage": safe_float(row[6]),
            "location": row[7],
            "last_seen": row[8],
            "status": status
        })

    # after building device list
    known_ips = set([d["ip_address"] for d in devices])
    # Scan devices using ping
    ping_devices = set(scan_network())

    # Scan devices using ARP
    arp_results = scan_network_arp()
    arp_devices = set([d["ip"] for d in arp_results])

    # Merge both scans
    all_devices = ping_devices.union(arp_devices)

    ignored_ips = {"192.168.1.1", "192.168.1.33"}

    rogue_devices = []

    # create arp lookup table
    arp_table = {d["ip"]: d["mac"] for d in arp_results}

    trusted_macs = set(m for m in trusted_macs if m)

    for ip in all_devices:

        # 🔥 check if device is actually alive
        response = subprocess.call(f"ping -n 1 -w 300 {ip}", shell=True)

        if response != 0:
            continue  # ❌ skip offline/ghost devices

        mac = arp_table.get(ip)

        if not mac:
            mac = get_mac_from_arp_cache(ip)

        if (
                ip not in trusted_ips and
                mac not in trusted_macs and
                ip not in ignored_ips
        ):
            rogue_devices.append({
                "ip": ip,
                "mac": mac,
                "status": "Unauthorized Device"
            })

    total_devices = len(devices)
    online_devices = len([d for d in devices if d["status"] == "ONLINE"])
    offline_devices = len([d for d in devices if d["status"] == "OFFLINE"])
    rogue_count = len(rogue_devices)
    trusted_count = len(trusted_ips)

    return render_template(
        "dashboard.html",
        devices=devices,
        rogue_devices=rogue_devices,
        trusted_devices=trusted_devices,
        total_devices=total_devices,
        online_devices=online_devices,
        offline_devices=offline_devices,
        rogue_count=rogue_count,
        trusted_count=trusted_count
    )
# ---------------------------
# Database Initialization
# ---------------------------
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS devices
                   (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                        hostname TEXT,
                        ip_address TEXT,
                        mac_address TEXT UNIQUE,
                        os TEXT,
                        cpu_usage REAL,
                        ram_usage REAL,
                        location TEXT,
                        last_seen TEXT
                   )
                   """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS trusted_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE,
        mac_address TEXT,
        device_name TEXT,
        location TEXT
    )
    """)

    conn.commit()
    conn.close()
# ---------------------------
# Receive Data from Clients
# ---------------------------
@app.route("/api/device", methods=["POST"])
def receive_device_data():
    try:
        data = request.json

        hostname = data.get("hostname")
        ip_address = data.get("ip_address")
        mac_address = data.get("mac_address")
        os_name = data.get("os")
        cpu_usage = data.get("cpu_usage")
        ram_usage = data.get("ram_usage")
        location = data.get("location", "Unknown")

        last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # check by MAC (unique device)
        cursor.execute("SELECT id FROM devices WHERE mac_address = ?", (mac_address,))
        device = cursor.fetchone()

        if device:
            # ✅ UPDATE existing device
            cursor.execute("""
                UPDATE devices
                SET hostname=?,
                    ip_address=?,
                    os=?,
                    cpu_usage=?,
                    ram_usage=?,
                    location=?,
                    last_seen=?
                WHERE mac_address=?
            """, (hostname, ip_address, os_name, cpu_usage, ram_usage, location, last_seen, mac_address))

        else:
            # ✅ INSERT new device
            cursor.execute("""
                INSERT INTO devices
                (hostname, ip_address, mac_address, os, cpu_usage, ram_usage, location, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (hostname, ip_address, mac_address, os_name, cpu_usage, ram_usage, location, last_seen))

        conn.commit()
        conn.close()

        return jsonify({"status": "success"})

    except Exception as e:
        print("ERROR:", e)
        return jsonify({"status": "error", "message": str(e)})
# View All Devices
# ---------------------------
@app.route("/api/devices", methods=["GET"])
def get_devices():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM devices")
    rows = cursor.fetchall()
    conn.close()

    devices = []
    for row in rows:
        devices.append({
            "id": row[0],
            "hostname": row[1],
            "ip_address": row[2],
            "mac_address": row[3],
            "os": row[4],
            "cpu_usage": row[5],
            "ram_usage": row[6],
            "location": row[7],
            "last_seen": row[8]
        })

    return jsonify(devices)

@app.route("/scan-network")
def scan_network_route():
    devices = scan_network()
    return jsonify(devices)

@app.route("/scan-arp")
def scan_arp():

    devices = scan_network_arp()

    return jsonify(devices)

@app.route("/detect-rogue")
def detect_rogue_devices():
    ping_devices = set(scan_network())
    arp_results = scan_network_arp()
    arp_devices = set([d["ip"] for d in arp_results])

    all_devices = ping_devices.union(arp_devices)

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT ip_address FROM devices")
    db_devices = cursor.fetchall()
    conn.close()

    known_ips = [d[0] for d in db_devices]

    ignored_ips = {"192.168.1.1", "192.168.1.33"}

    rogue_devices = []

    for device in arp_results:
        ip = device["ip"]
        mac = device["mac"]

        if ip in all_devices and ip not in known_ips and ip not in ignored_ips:
            rogue_devices.append({
                "ip": ip,
                "mac": mac
            })

    return jsonify({
        "rogue_devices": rogue_devices
    })

@app.route("/approve-device", methods=["POST"])
def approve_device():

    ip = request.form.get("ip")
    mac = request.form.get("mac")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT ip_address FROM trusted_devices WHERE ip_address=?", (ip,))
    exists = cursor.fetchone()

    if not exists:
        cursor.execute("""
        INSERT INTO trusted_devices
        (ip_address, mac_address, device_name, location)
        VALUES (?, ?, ?, ?)
        """, (ip, mac, "Approved Device", "Network"))

    conn.commit()
    conn.close()

    return jsonify({"status": "success"})

@app.route("/disapprove-device", methods=["POST"])
def disapprove_device():

    ip = request.form.get("ip")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM trusted_devices WHERE ip_address=?",
        (ip,)
    )

    conn.commit()
    conn.close()

    return jsonify({"status": "success"})

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)

