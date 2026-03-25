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
def verify_api():
    return request.headers.get("API-KEY") == API_KEY
def get_db():
    conn = sqlite3.connect(DATABASE, timeout=5, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

analytics_history = {
    "timestamps": [],
    "cpu_avg": [],
    "total_devices": [],
    "rogue_count": []
}

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
        try:
            print("🔍 Scanning network...")

            ping_devices = set(scan_network())
            arp_results = scan_network_arp()

            # Merge devices
            arp_ips = set(d["ip"] for d in arp_results)
            all_devices = arp_ips.union(ping_devices)

            with lock:
                network_cache["devices"] = all_devices
                network_cache["arp"] = arp_results
                network_cache["last_scan"] = datetime.now()

            # 📊 STORE ANALYTICS
            try:
                conn = get_db()
                cursor = conn.cursor()

                # CPU avg
                cursor.execute("SELECT cpu_usage, last_seen FROM devices")
                rows = cursor.fetchall()

                valid_cpu = []
                now = datetime.now()

                for cpu, last_seen in rows:
                    try:
                        last_seen_time = datetime.strptime(str(last_seen), "%Y-%m-%d %H:%M:%S")
                        if (now - last_seen_time).total_seconds() <= 30:
                            valid_cpu.append(float(cpu))
                    except:
                        continue

                avg_cpu = sum(valid_cpu) / len(valid_cpu) if valid_cpu else 0

                # Trusted devices
                cursor.execute("SELECT ip_address, mac_address FROM trusted_devices")
                trusted_rows = cursor.fetchall()

                conn.close()

                trusted_ips = set(r[0] for r in trusted_rows)
                trusted_macs = set(r[1] for r in trusted_rows)

                rogue_now = 0
                for d in arp_results:
                    mac = normalize_mac(d["mac"])
                    ip = d["ip"]

                    if mac not in trusted_macs and ip not in trusted_ips:
                        rogue_now += 1

                with lock:
                    analytics_history["timestamps"].append(datetime.now().strftime("%H:%M:%S"))
                    analytics_history["cpu_avg"].append(avg_cpu)
                    analytics_history["total_devices"].append(len(all_devices))
                    analytics_history["rogue_count"].append(rogue_now)

                MAX_POINTS = 20

                for key in analytics_history:
                    if len(analytics_history[key]) > MAX_POINTS:
                        analytics_history[key].pop(0)

            except Exception as e:
                print("Analytics error:", e)

            print(f"✅ Found {len(all_devices)} devices")

        except Exception as e:
            print("Scan error:", e)

        time.sleep(10)

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

    device_map = {}

    # DB devices
    for d in devices:
        device_map[d["ip_address"]] = {
            "status": d["status"]
        }

    # ARP devices (REAL NETWORK)
    for ip in arp_map:
        if ip not in device_map:
            device_map[ip] = {
                "status": "ONLINE"
            }

    final_devices = list(device_map.values())

    total_devices = len(final_devices)
    online_devices = len([d for d in final_devices if d["status"] == "ONLINE"])
    offline_devices = total_devices - online_devices

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

    print("APPROVE REQUEST:", ip, mac)

    if not mac or mac == "unknown":
        return jsonify({"status": "error", "message": "Invalid MAC"})

    conn = get_db()
    cursor = conn.cursor()

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

    return jsonify({
        "devices": devices,
        "rogue": rogue,
        "total": len(devices),
        "online": len([d for d in devices if d["status"] == "ONLINE"]),
        "offline": len([d for d in devices if d["status"] == "OFFLINE"]),
        "rogue_count": len(rogue),
        "trusted": trusted_list  #  FIXED
    })

def detect_rogue_logic(trusted_macs, trusted_ips):

    current_time = datetime.now()

    trusted_macs = set(normalize_mac(m) for m in trusted_macs)

    #  USE ONLY ARP (REAL DEVICES)
    with lock:
        arp_results = list(network_cache["arp"])
    arp_table = {d["ip"]: normalize_mac(d["mac"]) for d in arp_results}

    all_devices = set(arp_table.keys())

    ignored_ips = {"192.168.1.1"}

    #  UPDATE CACHE
    with lock:
        for ip in all_devices:
            last_seen_devices[ip] = current_time

    #  REMOVE OLD DEVICES (ANTI-GHOST)
    to_delete = []
    with lock:
        items = list(last_seen_devices.items())

    for ip, seen_time in items:
        if (current_time - seen_time).total_seconds() > 120:
            to_delete.append(ip)

    with lock:
        for ip in to_delete:
            del last_seen_devices[ip]

    with lock:
        stable_devices = list(last_seen_devices.keys())

    rogue_devices = {}

    for ip in stable_devices:

        if ip in ignored_ips:
            continue

        mac = arp_table.get(ip)

        #  fallback to ARP cache
        if not mac or mac == "unknown":
            mac = normalize_mac(get_mac_from_arp_cache(ip))

        #  still unknown → skip
        if not mac or mac == "unknown":
            continue

        if mac not in trusted_macs and ip not in trusted_ips:
            rogue_devices[ip] = {
                "ip": ip,
                "mac": mac,
                "status": "Unauthorized Device"
            }

    return list(rogue_devices.values())

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

        with ThreadPoolExecutor(max_workers=threads) as executor:

            futures = []

            for port in ports:
                futures.append(executor.submit(scan_single_port, ip, port, timeout))

            for future in as_completed(futures):
                result = future.result()
                if result:
                    yield f"data: {result}\n\n"

        yield "data: done\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")

if __name__ == "__main__":
    init_db()

    scanner_thread = threading.Thread(target=background_scanner, daemon=True)
    scanner_thread.start()

    app.run(host="0.0.0.0", port=5000, debug=True)

