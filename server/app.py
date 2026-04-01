from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify, session, redirect, render_template, Response, stream_with_context
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, threading, time, socket
from arp_scanner import scan_network_arp
from network_scanner import scan_network
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO


app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.secret_key = os.urandom(24)

DATABASE = "sccsims.db"
last_seen_devices = {}
lock = threading.Lock()

os.environ["SCCSIMS_API_KEY"] = "secret123"
API_KEY = os.getenv("SCCSIMS_API_KEY", "fallback_dev_key")

scan_control = {"stop": False}
mac_ip_history = {}   # {mac: ip}
ip_mac_history = {}   # {ip: (mac, time)}
rogue_cache = []
analytics_history = {
    "timestamps":    [],
    "cpu_avg":       [],
    "total_devices": [],
    "rogue_count":   []
}

network_cache = {
    "devices": [],
    "arp":     []
}


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def verify_api():
    return request.headers.get("API-KEY") == API_KEY

def get_db():
    return sqlite3.connect(DATABASE, timeout=10, check_same_thread=False)

def safe_float(val):
    try:
        return float(val)
    except:
        return 0.0

def normalize_mac(mac):
    if not mac:
        return "unknown"
    return mac.lower().replace("-", ":")

def fmt_timestamp(ts_str):
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt.strftime("%d %b %Y  %H:%M:%S")
    except:
        return ts_str


# ─────────────────────────────────────────────
# DATABASE INIT
# ─────────────────────────────────────────────

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname    TEXT,
            ip_address  TEXT,
            mac_address TEXT UNIQUE,
            os          TEXT,
            cpu_usage   REAL,
            ram_usage   REAL,
            location    TEXT,
            last_seen   TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS trusted_devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address  TEXT UNIQUE,
            mac_address TEXT,
            device_name TEXT,
            location    TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rogue_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT,
            mac         TEXT,
            attack_type TEXT,
            first_seen  TEXT,
            last_seen   TEXT
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mac         ON devices(mac_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip          ON devices(ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_trusted_mac ON trusted_devices(mac_address)")

    cursor.execute("SELECT id FROM users WHERE username=?", ("admin",))
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", generate_password_hash("admin123"))
        )

    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# BACKGROUND SCANNER
# ─────────────────────────────────────────────

def background_scanner():
    global network_cache

    while True:
        start_time = time.time()
        try:
            print("🔍 Scanning network...")

            with ThreadPoolExecutor(max_workers=2) as executor:
                ping_future = executor.submit(scan_network)
                arp_future  = executor.submit(scan_network_arp)
                ping_devices = set(ping_future.result())
                arp_results  = arp_future.result()

            arp_ips     = {d["ip"] for d in arp_results}
            all_devices = arp_ips.union(ping_devices)

            with lock:
                network_cache = {
                    "devices":   list(all_devices),
                    "arp":       arp_results,
                    "last_scan": datetime.now()
                }

            # Analytics update
            try:
                conn   = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT cpu_usage FROM devices")
                cpu_values = [safe_float(r[0]) for r in cursor.fetchall()]
                conn.close()

                avg_cpu = sum(cpu_values) / len(cpu_values) if cpu_values else 0

                conn   = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT ip_address, mac_address FROM trusted_devices")
                trusted_rows = cursor.fetchall()
                conn.close()

                trusted_ips  = set(r[0] for r in trusted_rows)
                trusted_macs = set(r[1] for r in trusted_rows)

                global rogue_cache

                rogue_devices = detect_rogue_logic(trusted_macs, trusted_ips)

                with lock:
                    rogue_cache = rogue_devices.copy()

                timestamp     = datetime.now().strftime("%H:%M:%S")

                MAX_POINTS = 20
                analytics_history["timestamps"].append(timestamp)
                analytics_history["cpu_avg"].append(round(avg_cpu, 2))
                analytics_history["total_devices"].append(len(all_devices))
                analytics_history["rogue_count"].append(len(rogue_devices))

                for key in analytics_history:
                    if len(analytics_history[key]) > MAX_POINTS:
                        analytics_history[key].pop(0)

            except Exception as e:
                print("Analytics Error:", e)

            print(f"✅ Scan done — {len(all_devices)} devices found")

        except Exception as e:
            print("❌ Scan error:", e)

        elapsed    = time.time() - start_time
        sleep_time = max(5, 10 - elapsed)
        time.sleep(sleep_time)

def safe_background():
    while True:
        try:
            background_scanner()
        except Exception as e:
            print("🔥 Scanner crashed, restarting in 3s...", e)
            time.sleep(3)


# ─────────────────────────────────────────────
# ROGUE DETECTION
# ─────────────────────────────────────────────

def log_rogue_attack(ip, mac, attack_type):
    try:
        conn   = get_db()
        cursor = conn.cursor()
        now    = datetime.now().isoformat()

        cursor.execute("""
            SELECT id FROM rogue_history
            WHERE ip=? AND mac=? AND attack_type=?
        """, (ip, mac, attack_type))

        row = cursor.fetchone()
        if row:
            cursor.execute("UPDATE rogue_history SET last_seen=? WHERE id=?", (now, row[0]))
        else:
            cursor.execute("""
                INSERT INTO rogue_history (ip, mac, attack_type, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
            """, (ip, mac, attack_type, now, now))

        conn.commit()
        conn.close()
    except Exception as e:
        print("log_rogue_attack error:", e)


def detect_rogue_logic(trusted_macs, trusted_ips):
    current_time  = datetime.now()
    trusted_macs  = set(normalize_mac(m) for m in trusted_macs)

    with lock:
        arp_results = list(network_cache["arp"])

    arp_table    = {d["ip"]: normalize_mac(d["mac"]) for d in arp_results}
    rogue_devices = []
    ip_seen       = {}
    mac_seen      = {}

    for ip, mac in arp_table.items():
        if not mac or mac == "unknown":
            continue

        status_list = []

        # 1. Unauthorized device
        if mac not in trusted_macs:
            status_list.append("Unauthorized Device")

        # 2. MAC spoofing — IP changed MAC within 60s
        if ip in ip_mac_history:
            old_mac, last_time = ip_mac_history[ip]
            if old_mac != mac and (current_time - last_time).total_seconds() < 60:
                status_list.append("⚠ MAC Spoofing Detected")
        ip_mac_history[ip] = (mac, current_time)

        # 3. IP spoofing — MAC using different IP
        if mac in mac_ip_history:
            old_ip = mac_ip_history[mac]
            if old_ip != ip:
                status_list.append("⚠ IP Spoofing Detected")
        mac_ip_history[mac] = ip

        # 4. Duplicate IP — two MACs share same IP
        if ip in ip_seen and ip_seen[ip] != mac:
            status_list.append("⚠ Duplicate IP Conflict")
        ip_seen[ip] = mac

        # 5. Duplicate MAC — same MAC on two IPs
        if mac in mac_seen and mac_seen[mac] != ip:
            status_list.append("⚠ Duplicate MAC Detected")
        mac_seen[mac] = ip

        if status_list:
            status = " | ".join(status_list)
            print(f"🚨 ROGUE: {ip} {mac} → {status}")
            if ip not in [r["ip"] for r in rogue_devices]:
                log_rogue_attack(ip, mac, status)

            rogue_devices.append({"ip": ip, "mac": mac, "status": status})

    return rogue_devices


# ─────────────────────────────────────────────
# ROUTES — AUTH
# ─────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn   = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session["user"] = username
            return redirect("/")
        return render_template("login.html", error="Invalid Credentials")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ─────────────────────────────────────────────
# ROUTES — DASHBOARD
# ─────────────────────────────────────────────

@app.route("/")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices")
    rows = cursor.fetchall()
    cursor.execute("SELECT ip_address, mac_address FROM trusted_devices")
    trusted_rows = cursor.fetchall()
    conn.close()

    current_time = datetime.now()
    trusted_ips  = set(r[0] for r in trusted_rows)
    trusted_macs = set(r[1] for r in trusted_rows)
    trusted_devices = [{"ip": r[0], "mac": r[1]} for r in trusted_rows]

    devices = []
    for row in rows:
        try:
            last_seen_time = datetime.strptime(str(row[8]), "%Y-%m-%d %H:%M:%S") if row[8] else current_time
        except:
            last_seen_time = current_time

        time_diff = (current_time - last_seen_time).total_seconds()
        status    = "ONLINE" if time_diff <= 15 else "OFFLINE"

        devices.append({
            "id":          row[0],
            "hostname":    row[1],
            "ip_address":  row[2],
            "mac_address": row[3],
            "os":          row[4],
            "cpu_usage":   safe_float(row[5]),
            "ram_usage":   safe_float(row[6]),
            "location":    row[7],
            "last_seen":   row[8],
            "status":      status
        })

    with lock:
        rogue_devices = list(rogue_cache)

    with lock:
        arp_results = list(network_cache["arp"])

    arp_map        = {d["ip"]: d["mac"] for d in arp_results}
    arp_ips        = set(arp_map.keys())
    db_ips         = set(d["ip_address"] for d in devices)
    trusted_ip_set = set(d["ip"] for d in trusted_devices)

    # Union of ALL known IPs
    all_ips    = arp_ips | db_ips | trusted_ip_set
    device_map = {d["ip_address"]: d for d in devices}

    final_devices = []
    for ip in all_ips:
        if ip in arp_ips:
            status = "ONLINE"
        elif ip in device_map:
            status = device_map[ip]["status"]
        else:
            status = "OFFLINE"
        final_devices.append({"ip": ip, "status": status})

    # Deduplicate
    unique        = {d["ip"]: d for d in final_devices}
    final_devices = list(unique.values())

    total_devices  = len(final_devices)
    online_devices = sum(1 for d in final_devices if d["status"] == "ONLINE")
    offline_devices= total_devices - online_devices
    rogue_count    = len(set(d["ip"] for d in rogue_devices))
    trusted_count  = len(trusted_ips)

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


# ─────────────────────────────────────────────
# ROUTES — AGENT API
# ─────────────────────────────────────────────

@app.route("/api/device", methods=["POST"])
def receive_device_data():
    if not verify_api():
        return jsonify({"error": "Unauthorized"}), 403
    try:
        data = request.json or {}

        hostname    = data.get("hostname")
        ip_address  = data.get("ip_address")
        mac_address = data.get("mac_address")
        os_name     = data.get("os")
        cpu_usage   = data.get("cpu_usage")
        ram_usage   = data.get("ram_usage")
        location    = data.get("location", "Unknown")
        last_seen   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if not mac_address:
            return jsonify({"status": "error", "message": "Missing MAC"})

        mac_address = normalize_mac(mac_address)

        conn   = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM devices WHERE mac_address=?", (mac_address,))
        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
                UPDATE devices
                SET hostname=?, ip_address=?, os=?,
                    cpu_usage=?, ram_usage=?, location=?, last_seen=?
                WHERE mac_address=?
            """, (hostname, ip_address, os_name, cpu_usage, ram_usage, location, last_seen, mac_address))
        else:
            cursor.execute("""
                INSERT INTO devices
                (hostname, ip_address, mac_address, os, cpu_usage, ram_usage, location, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (hostname, ip_address, mac_address, os_name, cpu_usage, ram_usage, location, last_seen))

        conn.commit()
        conn.close()
        return jsonify({"status": "success"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/devices", methods=["GET"])
def get_devices():
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices")
    rows = cursor.fetchall()
    conn.close()

    return jsonify([{
        "id":          row[0],
        "hostname":    row[1],
        "ip_address":  row[2],
        "mac_address": row[3],
        "os":          row[4],
        "cpu_usage":   row[5],
        "ram_usage":   row[6],
        "location":    row[7],
        "last_seen":   row[8]
    } for row in rows])


# ─────────────────────────────────────────────
# ROUTES — DEVICE MANAGEMENT
# ─────────────────────────────────────────────

@app.route("/approve-device", methods=["POST"])
def approve_device():
    ip  = request.form.get("ip")
    mac = normalize_mac(request.form.get("mac"))

    if not mac or mac == "unknown":
        return jsonify({"status": "error", "message": "Invalid MAC"})

    conn   = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM trusted_devices WHERE mac_address=?", (mac,))
    exists = cursor.fetchone()

    if not exists:
        cursor.execute("""
            INSERT INTO trusted_devices (ip_address, mac_address, device_name, location)
            VALUES (?, ?, ?, ?)
        """, (ip, mac, "Approved Device", "Network"))
        print(f"✅ Approved: {ip} ({mac})")
    else:
        # Update IP in case it changed (DHCP)
        cursor.execute("UPDATE trusted_devices SET ip_address=? WHERE mac_address=?", (ip, mac))
        print(f"ℹ️  Already trusted, updated IP: {ip} ({mac})")

    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


@app.route("/disapprove-device", methods=["POST"])
def disapprove_device():
    mac = request.form.get("mac")

    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM trusted_devices WHERE mac_address=?", (mac,))
    conn.commit()
    conn.close()

    return jsonify({"status": "success"})


# ─────────────────────────────────────────────
# ROUTES — LIVE DATA (for dashboard polling)
# ─────────────────────────────────────────────

@app.route("/api/live-data")
def live_data():
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices")
    rows = cursor.fetchall()
    cursor.execute("SELECT ip_address, mac_address FROM trusted_devices")
    trusted_rows = cursor.fetchall()
    conn.close()

    current_time = datetime.now()
    devices = []

    for row in rows:
        try:
            last_seen_time = datetime.strptime(str(row[8]), "%Y-%m-%d %H:%M:%S")
        except:
            last_seen_time = current_time

        status = "ONLINE" if (current_time - last_seen_time).total_seconds() <= 30 else "OFFLINE"

        devices.append({
            "hostname": row[1],
            "ip":       row[2],
            "cpu":      safe_float(row[5]),
            "ram":      safe_float(row[6]),
            "status":   status
        })

    trusted_ips  = set(r[0] for r in trusted_rows)
    trusted_macs = set(r[1] for r in trusted_rows)
    trusted_list = [{"ip": r[0], "mac": r[1]} for r in trusted_rows]

    with lock:
        rogue = list(rogue_cache)

    with lock:
        arp_results = list(network_cache["arp"])
    arp_ips = set(d["ip"] for d in arp_results)

    # Union of ALL known IPs including trusted (was missing trusted before)
    all_ips = (
        set(d["ip"] for d in devices)
        | set(r["ip"] for r in rogue)
        | set(t["ip"] for t in trusted_list)
    )

    final = []
    for ip in all_ips:
        if ip in arp_ips:
            status = "ONLINE"
        else:
            status = "OFFLINE"
            for d in devices:
                if d["ip"] == ip:
                    status = d["status"]
                    break

        final.append({"ip": ip, "status": status})

    return jsonify({
        "devices":     devices,
        "rogue":       rogue,
        "trusted":     trusted_list,
        "total":       len(final),
        "online":      sum(1 for d in final if d["status"] == "ONLINE"),
        "offline":     sum(1 for d in final if d["status"] == "OFFLINE"),
        "rogue_count": len(set(r["ip"] for r in rogue))
    })

@app.route("/generate-report")
def generate_report():
    if "user" not in session:
        return redirect("/login")

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer)

    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph("SCCSIMS Security Report", styles['Title']))
    elements.append(Spacer(1, 10))

    # Timestamp
    now = datetime.now().strftime("%d %B %Y %H:%M:%S")
    elements.append(Paragraph(f"Generated on: {now}", styles['Normal']))
    elements.append(Spacer(1, 15))

    # Fetch data
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT hostname, ip_address, os, cpu_usage, ram_usage, location FROM devices")
    devices = cursor.fetchall()

    cursor.execute("SELECT ip_address, mac_address FROM trusted_devices")
    trusted = cursor.fetchall()

    cursor.execute("""
        SELECT ip, mac, attack_type, last_seen 
        FROM rogue_history ORDER BY datetime(last_seen) DESC LIMIT 5
    """)
    attacks = cursor.fetchall()

    conn.close()

    # ───────── SUMMARY ─────────
    elements.append(Paragraph("Network Summary", styles['Heading2']))

    summary_data = [
        ["Total Devices", str(len(devices))],
        ["Trusted Devices", str(len(trusted))],
        ["Recent Attacks", str(len(attacks))]
    ]

    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.grey),
        ("GRID", (0,0), (-1,-1), 0.5, colors.black)
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))

    # ───────── DEVICES TABLE ─────────
    elements.append(Paragraph("Devices", styles['Heading2']))

    device_data = [["Hostname", "IP", "OS", "CPU%", "RAM%", "Location"]]

    for d in devices:
        device_data.append([
            d[0], d[1], d[2],
            str(d[3]), str(d[4]), d[5]
        ])

    device_table = Table(device_data)
    device_table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.25, colors.black),
        ("BACKGROUND", (0,0), (-1,0), colors.lightgrey)
    ]))
    elements.append(device_table)
    elements.append(Spacer(1, 20))

    # ───────── TRUSTED ─────────
    elements.append(Paragraph("Trusted Devices", styles['Heading2']))

    trusted_data = [["IP", "MAC"]]
    for t in trusted:
        trusted_data.append([t[0], t[1]])

    elements.append(Table(trusted_data))
    elements.append(Spacer(1, 20))

    # ───────── ATTACKS ─────────
    elements.append(Paragraph("Recent Attacks", styles['Heading2']))

    attack_data = [["IP", "MAC", "Type", "Last Seen"]]
    for a in attacks:
        attack_data.append([a[0], a[1], a[2], fmt_timestamp(a[3])])

    elements.append(Table(attack_data))

    # Build PDF
    doc.build(elements)

    buffer.seek(0)
    filename = f"SCCSIMS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        buffer,
        mimetype='application/pdf',
        headers = {"Content-Disposition": f"attachment;filename={filename}"}
    )

# ─────────────────────────────────────────────
# ROUTES — ANALYTICS & ATTACKER
# ─────────────────────────────────────────────

@app.route("/api/analytics")
def analytics():
    return jsonify(analytics_history)


@app.route("/api/last-attacker")
def last_attacker():
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip, mac, attack_type, last_seen
        FROM rogue_history
        ORDER BY datetime(last_seen) DESC
        LIMIT 1
    """)
    row = cursor.fetchone()
    conn.close()

    if row:
        return jsonify({
            "ip":        row[0],
            "mac":       row[1],
            "type":      row[2],
            "last_seen": fmt_timestamp(row[3])
        })

    return jsonify({"ip": None, "message": "No attacks yet"})


# ─────────────────────────────────────────────
# ROUTES — NETWORK SCAN
# ─────────────────────────────────────────────

@app.route("/scan-network")
def scan_network_route():
    return jsonify(scan_network())

@app.route("/scan-arp")
def scan_arp():
    return jsonify(scan_network_arp())

@app.route("/detect-rogue")
def detect_rogue_devices():
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, mac_address FROM trusted_devices")
    trusted_rows = cursor.fetchall()
    conn.close()

    trusted_ips  = set(r[0] for r in trusted_rows)
    trusted_macs = set(r[1] for r in trusted_rows)
    return jsonify({"rogue_devices": detect_rogue_logic(trusted_macs, trusted_ips)})


# ─────────────────────────────────────────────
# ROUTES — PORT SCANNER
# ─────────────────────────────────────────────

def scan_ports(ip, ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389]
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports


def scan_single_port(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None


@app.route("/scan-ports")
def scan_ports_route():
    ip         = request.args.get("ip")
    port_range = request.args.get("range", "")

    if not ip:
        return jsonify({"error": "IP required"}), 400

    ports = None
    if port_range and "-" in port_range:
        start, end = port_range.split("-")
        ports = list(range(int(start), int(end) + 1))

    return jsonify({"ip": ip, "open_ports": scan_ports(ip, ports)})


@app.route("/scan-ports-live")
def scan_ports_live():
    ip         = request.args.get("ip")
    port_range = request.args.get("range", "1-1024")
    speed      = request.args.get("speed", "normal")
    threads    = min(int(request.args.get("threads", 50)), 100)

    try:
        start, end = map(int, port_range.split("-"))
    except:
        return "data: error\n\n"

    if end - start > 5000:
        return "data: Range too large\n\n"

    ports   = list(range(start, end + 1))
    timeout = {"aggressive": 0.3, "stealth": 2}.get(speed, 0.8)

    def generate():
        scan_control["stop"] = False
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(scan_single_port, ip, p, timeout)
                       for p in ports if not scan_control["stop"]]
            for future in as_completed(futures):
                if scan_control["stop"]:
                    break
                result = future.result()
                if result:
                    yield f"data: {result}\n\n"
        yield "data: done\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/scan-ports-advanced", methods=["POST"])
def scan_ports_advanced():
    try:
        data       = request.json
        ip         = data.get("ip")
        speed      = data.get("speed", "normal")
        port_range = data.get("port_range", "1-1024")
        threads    = min(int(data.get("threads", 50)), 100)
        timeout    = {"aggressive": 0.3, "stealth": 2}.get(speed, 0.8)

        start, end = map(int, port_range.split("-"))
        ports      = list(range(start, end + 1))

        def scan_tcp(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            results = executor.map(scan_tcp, ports)

        return jsonify({"ip": ip, "open_ports": sorted(p for p in results if p)})

    except Exception as e:
        return jsonify({"error": "scan failed", "open_ports": []})


@app.route("/stop-scan")
def stop_scan():
    scan_control["stop"] = True
    return jsonify({"status": "stopped"})


# ─────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    scanner_thread = threading.Thread(target=safe_background, daemon=True)
    scanner_thread.start()

    app.run(host="0.0.0.0", port=5000, debug=True)