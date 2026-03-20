from flask import Flask, request, jsonify, session, redirect, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, subprocess, threading, time
from arp_scanner import scan_network_arp
from network_scanner import scan_network
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)# required for session

DATABASE = "sccsims.db"
last_seen_devices = {}

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



network_cache = {
    "devices": [],
    "arp": []
}

def background_scanner():
    global network_cache

    while True:
        try:
            print("🔍 Scanning network...")

            ping_devices = set(scan_network())
            arp_results = scan_network_arp()

            # ✅ Merge but prioritize ARP
            arp_ips = set([d["ip"] for d in arp_results])
            all_devices = arp_ips.union(ping_devices)

            network_cache["devices"] = all_devices
            network_cache["arp"] = arp_results
            network_cache["last_scan"] = datetime.now()

            print(f"✅ Found {len(all_devices)} devices")

        except Exception as e:
            print("Scan error:", e)

        time.sleep(5)

@app.route("/")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DATABASE, timeout=5, check_same_thread=False)
    cursor = conn.cursor()

    # Get all devices
    cursor.execute("SELECT * FROM devices")
    rows = cursor.fetchall()

    # Get trusted devices
    cursor.execute("SELECT ip_address, mac_address FROM trusted_devices")
    trusted_rows = cursor.fetchall()

    conn.close()

    devices = []
    current_time = datetime.now()

    trusted_ips = set([r[0] for r in trusted_rows])
    trusted_macs = set([r[1] for r in trusted_rows])

    trusted_devices = []

    for row in trusted_rows:
        trusted_devices.append({
            "ip": row[0],
            "mac": row[1]
        })

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

    rogue_devices = detect_rogue_logic(trusted_macs, trusted_ips)

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
    conn = sqlite3.connect(DATABASE, timeout=5, check_same_thread=False)
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
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    """)
    cursor.execute("SELECT * FROM users WHERE username=?", ("admin",))
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", generate_password_hash("admin123"))
        )
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

        conn = sqlite3.connect(DATABASE, timeout=5, check_same_thread=False)
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
        # print("ERROR:", e)
        return jsonify({"status": "error", "message": str(e)})
# View All Devices
# ---------------------------
@app.route("/api/devices", methods=["GET"])
def get_devices():
    conn = sqlite3.connect(DATABASE, timeout=5, check_same_thread=False)
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

    conn = sqlite3.connect(DATABASE, timeout=5, check_same_thread=False)
    cursor = conn.cursor()

    cursor.execute("SELECT ip_address, mac_address FROM trusted_devices")
    trusted_rows = cursor.fetchall()
    conn.close()

    trusted_ips = set([r[0] for r in trusted_rows])
    trusted_macs = set([r[1] for r in trusted_rows])

    rogue_devices = detect_rogue_logic(trusted_macs, trusted_ips)

    return jsonify({"rogue_devices": rogue_devices})

@app.route("/approve-device", methods=["POST"])
def approve_device():

    ip = request.form.get("ip")

    def normalize_mac(mac):
        if not mac:
            return "unknown"
        return mac.lower().replace("-", ":")

    ip = request.form.get("ip")
    mac = normalize_mac(request.form.get("mac"))

    print("APPROVE REQUEST:", ip, mac)

    if not mac or mac == "Unknown":
        return jsonify({"status": "error", "message": "Invalid MAC"})

    conn = sqlite3.connect(DATABASE, timeout=5, check_same_thread=False)
    cursor = conn.cursor()

    # 🔥 CHECK BY MAC (not IP)
    cursor.execute("SELECT mac_address FROM trusted_devices WHERE mac_address=?", (mac,))
    exists = cursor.fetchone()

    if not exists:
        cursor.execute("""
        INSERT INTO trusted_devices
        (ip_address, mac_address, device_name, location)
        VALUES (?, ?, ?, ?)
        """, (ip, mac.lower(), "Approved Device", "Network"))

        cursor.execute("SELECT * FROM trusted_devices")
        print("TRUSTED DEVICES:", cursor.fetchall())

    conn.commit()
    conn.close()

    return jsonify({"status": "success"})

@app.route("/disapprove-device", methods=["POST"])
def disapprove_device():
    mac = request.form.get("mac")

    conn = sqlite3.connect(DATABASE, timeout=5, check_same_thread=False)
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM trusted_devices WHERE mac_address=?",
        (mac,)
    )

    conn.commit()
    conn.close()

    return jsonify({"status": "success"})

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect(DATABASE, timeout=5, check_same_thread=False)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[2], password):
            session["user"] = username
            return redirect("/")
        else:
            return render_template("login.html", error="Invalid Credentials")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/api/live-data")
def live_data():

    conn = sqlite3.connect(DATABASE, timeout=5, check_same_thread=False)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM devices")
    rows = cursor.fetchall()

    cursor.execute("SELECT ip_address, mac_address FROM trusted_devices")
    trusted_rows = cursor.fetchall()

    conn.close()

    devices = []
    current_time = datetime.now()

    for row in rows:
        try:
            last_seen_time = datetime.strptime(str(row[8]), "%Y-%m-%d %H:%M:%S")
        except:
            last_seen_time = current_time

        status = "ONLINE" if (current_time - last_seen_time).total_seconds() <= 30 else "OFFLINE"

        devices.append({
            "hostname": row[1],
            "ip": row[2],
            "cpu": row[5],
            "ram": row[6],
            "status": status
        })

    trusted_ips = set([r[0] for r in trusted_rows])
    trusted_macs = set([r[1] for r in trusted_rows])

    rogue_devices = detect_rogue_logic(trusted_macs, trusted_ips)

    rogue = rogue_devices  # send full objects

    trusted_list = [{"ip": r[0], "mac": r[1]} for r in trusted_rows]
    if not devices and last_seen_devices:
        # fallback to cached devices
        for ip in last_seen_devices:
            devices.append({
                "hostname": "Unknown",
                "ip": ip,
                "cpu": 0,
                "ram": 0,
                "status": "ONLINE"
            })
    return jsonify({
        "devices": devices,
        "rogue": rogue,
        "total": len(devices),
        "online": len([d for d in devices if d["status"] == "ONLINE"]),
        "offline": len([d for d in devices if d["status"] == "OFFLINE"]),
        "rogue_count": len(rogue),
        "trusted": trusted_list  # ✅ FIXED
    })

def detect_rogue_logic(trusted_macs, trusted_ips):

    current_time = datetime.now()

    def normalize_mac(mac):
        if not mac:
            return "unknown"
        return mac.lower().replace("-", ":")

    trusted_macs = set(normalize_mac(m) for m in trusted_macs)

    # ✅ USE ONLY ARP (REAL DEVICES)
    arp_results = network_cache["arp"]
    arp_table = {d["ip"]: normalize_mac(d["mac"]) for d in arp_results}

    all_devices = set(arp_table.keys())

    ignored_ips = {"192.168.1.1"}

    # ✅ UPDATE CACHE
    for ip in all_devices:
        last_seen_devices[ip] = current_time

    # ✅ REMOVE OLD DEVICES (ANTI-GHOST)
    to_delete = []
    for ip, seen_time in last_seen_devices.items():
        if (current_time - seen_time).total_seconds() > 120:
            to_delete.append(ip)

    for ip in to_delete:
        del last_seen_devices[ip]

    stable_devices = list(last_seen_devices.keys())

    rogue_devices = {}

    for ip in stable_devices:

        if ip in ignored_ips:
            continue

        mac = arp_table.get(ip)

        # ✅ fallback to ARP cache
        if not mac or mac == "unknown":
            mac = normalize_mac(get_mac_from_arp_cache(ip))

        # ❌ still unknown → skip
        if not mac or mac == "unknown":
            continue

        if mac not in trusted_macs and ip not in trusted_ips:
            rogue_devices[ip] = {
                "ip": ip,
                "mac": mac,
                "status": "Unauthorized Device"
            }

    return list(rogue_devices.values())

if __name__ == "__main__":
    init_db()

    scanner_thread = threading.Thread(target=background_scanner, daemon=True)
    scanner_thread.start()

    app.run(host="0.0.0.0", port=5000, debug=True)

