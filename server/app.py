from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify, session, redirect, render_template, Response, stream_with_context
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, subprocess, threading, time, socket
from arp_scanner import scan_network_arp
from network_scanner import scan_network
from datetime import datetime

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.secret_key = os.urandom(24)# required for session
DATABASE = "sccsims.db"
last_seen_devices = {}
lock = threading.Lock()
os.environ["SCCSIMS_API_KEY"] = "secret123"
API_KEY = os.getenv("SCCSIMS_API_KEY", "fallback_dev_key")
scan_control = {"stop" : False}
mac_ip_history = {}   # {mac: ip}


def verify_api():
    return request.headers.get("API-KEY") == API_KEY

def get_db():
    return sqlite3.connect(DATABASE, timeout=10, check_same_thread=False)

analytics_history = {
    "timestamps": [],
    "cpu_avg": [],
    "total_devices": [],
    "rogue_count": []
}
ip_mac_history = {}
def scan_ports(ip, ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389]
    open_ports = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)

            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)

            sock.close()
        except:
            pass

    return open_ports

def safe_background():
    while True:
        try:
            background_scanner()
        except Exception as e:
            print("🔥 Scanner crashed, restarting...", e)
            time.sleep(3)

@app.route("/scan-ports-advanced", methods=["POST"])
def scan_ports_advanced():
    try:
        data = request.json

        ip = data.get("ip")
        speed = data.get("speed", "normal")
        port_range = data.get("port_range", "1-1024")
        threads = min(int(data.get("threads", 50)), 100)

        start, end = map(int, port_range.split("-"))
        ports = list(range(start, end + 1))

        # ⚡ speed control
        if speed == "aggressive":
            timeout = 0.3
        elif speed == "stealth":
            timeout = 2
        else:
            timeout = 0.8

        def scan_tcp(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(timeout)

                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    return port  # ✅ return instead of append

            except:
                return None

        # 🚀 THREAD POOL (SAFE + FAST)
        with ThreadPoolExecutor(max_workers=threads) as executor:
            results = executor.map(scan_tcp, ports)

        # ✅ collect results safely
        open_ports = [p for p in results if p is not None]

        return jsonify({
            "ip": ip,
            "open_ports": sorted(open_ports)
        })

    except Exception as e:
        print("ADV SCAN ERROR:", e)
        return jsonify({"error": "scan failed", "open_ports": []})

def get_mac_from_arp_cache(ip):
    if os.name == "nt":
        cmd = "arp -a"
    else:
        cmd = "arp -n"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=2).decode()
        for line in output.split("\n"):
            if ip in line:
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]


    except Exception as e:
        print("ARP Error:", e)

    return "Unknown"

network_cache = {
    "devices": [],
    "arp": []
}

def background_scanner():
    global network_cache

    while True:
        start_time = time.time()

        try:
            print("🔍 Optimized Scan Running...")

            # 🚀 PARALLEL SCAN
            with ThreadPoolExecutor(max_workers=2) as executor:
                ping_future = executor.submit(scan_network)
                arp_future = executor.submit(scan_network_arp)

                ping_devices = set(ping_future.result())
                arp_results = arp_future.result()

            arp_ips = {d["ip"] for d in arp_results}
            all_devices = arp_ips.union(ping_devices)

            with lock:
                network_cache = {
                    "devices": list(all_devices),
                    "arp": arp_results,
                    "last_scan": datetime.now()
                }

            print(f"✅ Devices: {len(all_devices)}")

        except Exception as e:
            print("❌ Scan error:", e)

        # ⏱ SMART SLEEP (adaptive)
        elapsed = time.time() - start_time
        sleep_time = max(5, 10 - elapsed)
        time.sleep(sleep_time)

def safe_float(val):
    try:
        return float(val)
    except:
        return 0

@app.route("/")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    conn = get_db()
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

        #  FORCE numeric safety
        time_diff = float(time_diff)

        status = "ONLINE" if time_diff <= 15 else "OFFLINE"

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

    with lock:
        arp_results = list(network_cache["arp"])
    arp_map = {d["ip"]: d["mac"] for d in arp_results}

    final_devices = []

    arp_ips = set(arp_map.keys())
    db_ips = set([d["ip_address"] for d in devices])

    all_ips = arp_ips.union(db_ips)

    device_map = {d["ip_address"]: d for d in devices}

    for ip in all_ips:

        # ✅ PRIORITY 1 → ARP = REAL NETWORK PRESENCE
        if ip in arp_ips:
            status = "ONLINE"

        # ✅ PRIORITY 2 → DB fallback
        elif ip in device_map:
            status = device_map[ip]["status"]

        else:
            status = "OFFLINE"

        final_devices.append({
            "ip": ip,
            "status": status
        })

        final_devices.append({
            "ip": ip,
            "status": status
        })

    total_devices = len(final_devices)
    online_devices = sum(1 for d in final_devices if d["status"] == "ONLINE")
    offline_devices = sum(1 for d in final_devices if d["status"] == "OFFLINE")

    rogue_unique_ips = set(d["ip"] for d in rogue_devices)
    rogue_count = len(rogue_unique_ips)

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
    conn = get_db()
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
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mac ON devices(mac_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip ON devices(ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_trusted_mac ON trusted_devices(mac_address)")
    cursor.execute("SELECT * FROM users WHERE username=?", ("admin",))
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", generate_password_hash("admin123"))
        )
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS rogue_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        mac TEXT,
        attack_type TEXT,
        first_seen TEXT,
        last_seen TEXT
    )
    """)
    conn.commit()
    conn.close()
# ---------------------------
# Receive Data from Clients
# ---------------------------
@app.route("/api/device", methods=["POST"])
def receive_device_data():
    if not verify_api():
        return jsonify({"error": "Unauthorized"}), 403
    try:
        data = request.json or {}

        hostname = data.get("hostname")
        ip_address = data.get("ip_address")
        mac_address = data.get("mac_address")
        os_name = data.get("os")
        cpu_usage = data.get("cpu_usage")
        ram_usage = data.get("ram_usage")
        location = data.get("location", "Unknown")
        last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if not mac_address:
            return jsonify({"status": "error", "message": "Missing MAC"})

        conn = get_db()
        cursor = conn.cursor()

        # check by MAC (unique device)
        cursor.execute("SELECT id FROM devices WHERE mac_address = ?", (mac_address,))
        device = cursor.fetchone()

        if device:
            #  UPDATE existing device
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
            #  INSERT new device
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
    conn = get_db()
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

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT ip_address, mac_address FROM trusted_devices")
    trusted_rows = cursor.fetchall()
    conn.close()

    trusted_ips = set([r[0] for r in trusted_rows])
    trusted_macs = set([r[1] for r in trusted_rows])

    rogue_devices = detect_rogue_logic(trusted_macs, trusted_ips)

    return jsonify({"rogue_devices": rogue_devices})

def normalize_mac(mac):
    if not mac:
        return "unknown"
    return mac.lower().replace("-", ":")

@app.route("/approve-device", methods=["POST"])
def approve_device():

    ip = request.form.get("ip")
    mac = normalize_mac(request.form.get("mac"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO trusted_devices
    (ip_address, mac_address, device_name, location)
    VALUES (?, ?, ?, ?)
    """, (ip, mac, "Approved Device", "Network"))

    print("APPROVE REQUEST:", ip, mac)

    if not mac or mac == "unknown":
        return jsonify({"status": "error", "message": "Invalid MAC"})

    #  CHECK BY MAC (not IP)
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

    conn = get_db()
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

        conn = get_db()
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
    conn = get_db()
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

    all_ips = set([d["ip"] for d in devices]) | set([r["ip"] for r in rogue])

    final = []

    for ip in all_ips:
        status = "OFFLINE"

        for d in devices:
            if d["ip"] == ip:
                status = d["status"]

        for r in rogue:
            if r["ip"] == ip:
                status = "ONLINE"

        final.append({"ip": ip, "status": status})

    return jsonify({
        "devices": devices,
        "rogue": rogue,
        "total": len(final),
        "online": sum(1 for d in final if d["status"] == "ONLINE"),
        "offline": sum(1 for d in final if d["status"] == "OFFLINE"),
        "rogue_count": len(set(r["ip"] for r in rogue)),
        "trusted": trusted_list
    })

def log_rogue_attack(ip, mac, attack_type):
    conn = get_db()
    cursor = conn.cursor()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check if already exists
    cursor.execute("""
        SELECT id FROM rogue_history
        WHERE ip=? AND mac=? AND attack_type=?
    """, (ip, mac, attack_type))

    row = cursor.fetchone()

    if row:
        # Update last seen
        cursor.execute("""
            UPDATE rogue_history
            SET last_seen=?
            WHERE id=?
        """, (now, row[0]))
    else:
        # Insert new
        cursor.execute("""
            INSERT INTO rogue_history (ip, mac, attack_type, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
        """, (ip, mac, attack_type, now, now))

    conn.commit()
    conn.close()

def detect_rogue_logic(trusted_macs, trusted_ips):

    current_time = datetime.now()
    trusted_macs = set(normalize_mac(m) for m in trusted_macs)

    with lock:
        arp_results = list(network_cache["arp"])

    arp_table = {d["ip"]: normalize_mac(d["mac"]) for d in arp_results}

    rogue_devices = []

    ip_seen = {}
    mac_seen = {}

    for ip, mac in arp_table.items():

        if not mac or mac == "unknown":
            continue

        status_list = []

        # ---------------------------
        # 1. Unauthorized Device
        # ---------------------------
        if mac not in trusted_macs:
            status_list.append("Unauthorized Device")

        # ---------------------------
        # 2. MAC Spoof Detection (Improved)
        # ---------------------------
        if ip in ip_mac_history:
            old_mac, last_time = ip_mac_history[ip]

            # only flag if recent change (within 60 sec)
            if old_mac != mac and (current_time - last_time).total_seconds() < 60:
                status_list.append("⚠ MAC Spoofing Detected")

        ip_mac_history[ip] = (mac, current_time)

        # ---------------------------
        # 3. IP Spoof Detection
        # ---------------------------
        if mac in mac_ip_history:
            old_ip = mac_ip_history[mac]

            if old_ip != ip:
                status_list.append("⚠ IP Spoofing Detected")

        mac_ip_history[mac] = ip

        # ---------------------------
        # 4. Duplicate IP Detection (FIXED)
        # ---------------------------
        if ip in ip_seen and ip_seen[ip] != mac:
            status_list.append("⚠ Duplicate IP Conflict")

        ip_seen[ip] = mac

        # ---------------------------
        # 5. Duplicate MAC Detection
        # ---------------------------
        if mac in mac_seen and mac_seen[mac] != ip:
            status_list.append("⚠ Duplicate MAC Detected")

        mac_seen[mac] = ip

        # ---------------------------
        # FINAL DECISION
        # ---------------------------
        if status_list:
            status = " | ".join(status_list)

            log_rogue_attack(ip, mac, status)

            rogue_devices.append({
                "ip": ip,
                "mac": mac,
                "status": status
            })

    return rogue_devices

@app.route("/api/last-attacker")
def last_attacker():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ip, mac, attack_type, last_seen
        FROM rogue_history
        ORDER BY last_seen DESC
        LIMIT 1
    """)

    row = cursor.fetchone()
    conn.close()

    if row:
        return jsonify({
            "ip": row[0],
            "mac": row[1],
            "type": row[2],
            "last_seen": row[3]
        })

    return jsonify({})

@app.route("/api/analytics")
def analytics():
    return jsonify(analytics_history)

@app.route("/scan-ports")
def scan_ports_route():
    ip = request.args.get("ip")
    protocol = request.args.get("protocol", "tcp")
    speed = request.args.get("speed", "normal")
    port_range = request.args.get("range", "")
    threads = int(request.args.get("threads", 10))

    if not ip:
        return jsonify({"error": "IP required"}), 400

    # default ports
    ports = None

    # custom range
    if port_range and "-" in port_range:
        start, end = port_range.split("-")
        ports = list(range(int(start), int(end)+1))

    open_ports = scan_ports(ip, ports)

    return jsonify({
        "ip": ip,
        "protocol": protocol,
        "speed": speed,
        "threads": threads,
        "open_ports": open_ports
    })

def scan_single_port(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            return port

    except:
        return None

@app.route("/scan-ports-live")
def scan_ports_live():

    ip = request.args.get("ip")
    port_range = request.args.get("range", "1-1024")
    speed = request.args.get("speed", "normal")
    threads = int(request.args.get("threads", 50))

    # 🔒 Safety limits
    threads = min(threads, 100)

    try:
        start, end = map(int, port_range.split("-"))
    except:
        return "data: error\n\n"

    if end - start > 5000:
        return "data: Range too large\n\n"

    if end < 1 or end > 65535:
        return "data: Invalid port range\n\n"

    ports = list(range(start, end + 1))

    # ⚡ speed control
    if speed == "aggressive":
        timeout = 0.3
    elif speed == "stealth":
        timeout = 2
    else:
        timeout = 0.8

    def generate():
        scan_control["stop"] = False

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []

            for port in ports:
                if scan_control["stop"]:
                    break

                futures.append(executor.submit(scan_single_port, ip, port, timeout))

            for future in as_completed(futures):
                if scan_control["stop"]:
                    break

                result = future.result()
                if result:
                    yield f"data: {result}\n\n"

        yield "data: done\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")

@app.route("/stop-scan")
def stop_scan():
    scan_control["stop"] = True
    return jsonify({"status": "stopped"})

if __name__ == "__main__":
    init_db()

    scanner_thread = threading.Thread(target=background_scanner, daemon=True)
    scanner_thread.start()

    app.run(host="0.0.0.0", port=5000, debug=True)

