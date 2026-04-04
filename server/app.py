import os
import socket
import sqlite3
import threading
import time
import io
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from io import BytesIO
import matplotlib
from flask import Flask, send_file, request, jsonify, session, redirect, render_template, Response, stream_with_context
from werkzeug.security import generate_password_hash, check_password_hash
from arp_scanner import scan_network_arp
from network_scanner import scan_network
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import tempfile
import logging

# ===== LOGGING SETUP =====
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "sccsims.log")

# Create custom logger
logger = logging.getLogger("sccsims")
logger.setLevel(logging.INFO)

# File handler (ONLY your logs go to file)
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.INFO)

formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
file_handler.setFormatter(formatter)

# Keep Flask logs in terminal only
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.ERROR)

logger.addHandler(file_handler)

logger.info("===== SCCSIMS SERVER STARTED =====")

from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, PageBreak
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4

app = Flask(__name__)
app.config.update({
    "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SAMESITE": "Lax",
    "SESSION_COOKIE_SECURE": False,
    "PERMANENT_SESSION_LIFETIME": timedelta(minutes=15)
})

app.secret_key = "secret456"

DATABASE = "sccsims.db"
last_seen_devices = {}
lock = threading.Lock()

os.environ["SCCSIMS_API_KEY"] = "secret123"
API_KEY = os.getenv("SCCSIMS_API_KEY", "fallback_dev_key")

scan_control = {"stop": False}
mac_ip_history = {}
ip_mac_history = {}
rogue_cache = []
analytics_history = {
    "timestamps":    [],
    "cpu_avg":       [],
    "ram_avg":       [],
    "total_devices": [],
    "rogue_count":   []
}

network_cache = {
    "devices": [],
    "arp":     []
}

# HELPERS
def verify_api():
    return request.headers.get("API-KEY") == API_KEY

def get_db():
    conn = sqlite3.connect(DATABASE, timeout=10, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def safe_float(val):
    try:
        return float(val)
    except Exception:
        return 0.0

def normalize_mac(mac):
    if not mac:
        return "unknown"
    return mac.lower().replace("-", ":")

def fmt_timestamp(ts_str):
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt.strftime("%d %b %Y  %H:%M:%S")
    except Exception:
        return ts_str

# DATABASE INIT
def init_db():
    conn   = get_db()
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
        CREATE TABLE IF NOT EXISTS scan_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ip        TEXT,
            ports     TEXT,
            high_risk INTEGER,
            time      TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rogue_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT,
            mac         TEXT,
            attack_type TEXT,
            detected_at TEXT
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
                prev_seen   TEXT,
                last_seen   TEXT,
                count       INTEGER DEFAULT 1
            )
        """)
    # # Migrate existing table if columns are missing (safe to run every time)
    # for col, default in [("prev_seen", "NULL"), ("count", "1")]:
    #     try:
    #         cursor.execute(f"ALTER TABLE rogue_history ADD COLUMN {col} TEXT DEFAULT {default}")
    #     except Exception:
    #         pass

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

# BACKGROUND SCANNER
def background_scanner():
    global network_cache

    while True:
        start_time = time.time()
        try:
            logger.info("Network scan started")
            with ThreadPoolExecutor(max_workers=2) as executor:
                ping_future  = executor.submit(scan_network)
                arp_future   = executor.submit(scan_network_arp)
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

            try:
                conn   = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT cpu_usage, ram_usage FROM devices")
                rows = cursor.fetchall()
                conn.close()

                cpu_values = [safe_float(r[0]) for r in rows]
                ram_values = [safe_float(r[1]) for r in rows]
                avg_cpu = sum(cpu_values) / len(cpu_values) if cpu_values else 0
                avg_ram = sum(ram_values) / len(ram_values) if ram_values else 0

                conn   = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT ip_address, mac_address FROM trusted_devices")
                trusted_rows = cursor.fetchall()
                conn.close()

                trusted_macs = set(r[1] for r in trusted_rows)
                trusted_ips  = set(r[0] for r in trusted_rows)

                global rogue_cache
                rogue_devices = detect_rogue_logic(trusted_macs, trusted_ips)

                with lock:
                    rogue_cache = rogue_devices.copy()

                timestamp = datetime.now().strftime("%H:%M:%S")

                MAX_POINTS = 20
                analytics_history["timestamps"].append(timestamp)
                analytics_history["cpu_avg"].append(round(avg_cpu, 2))
                analytics_history["ram_avg"].append(round(avg_ram, 2))
                analytics_history["total_devices"].append(len(all_devices))
                analytics_history["rogue_count"].append(len(rogue_devices))

                for key in analytics_history:
                    if len(analytics_history[key]) > MAX_POINTS:
                        analytics_history[key].pop(0)

            except Exception as e:
                print("Analytics Error:", e)

            logger.info(f"Scan completed: {len(all_devices)} devices found")

        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            print("Scan error:", e)

        elapsed    = time.time() - start_time
        sleep_time = max(5, 10 - elapsed)
        time.sleep(sleep_time)

def safe_background():
    while True:
        try:
            background_scanner()
        except Exception as e:
            print("Scanner crashed, restarting in 3s...", e)
            time.sleep(3)

# ROGUE DETECTION
def log_rogue_attack(ip, mac, attack_type):
    try:
        conn   = get_db()
        cursor = conn.cursor()
        now    = datetime.now().isoformat()

        cursor.execute("""
            SELECT id, last_seen, count FROM rogue_history
            WHERE ip=? AND mac=? AND attack_type=?
        """, (ip, mac, attack_type))

        row = cursor.fetchone()
        if row:
            row_id, current_last, current_count = row
            prev_count = current_count if current_count else 1
            cursor.execute("""
                UPDATE rogue_history
                SET prev_seen=?, last_seen=?, count=?
                WHERE id=?
            """, (current_last, now, prev_count + 1, row_id))
        else:
            cursor.execute("""
                INSERT INTO rogue_history (ip, mac, attack_type, first_seen, prev_seen, last_seen, count)
                VALUES (?, ?, ?, ?, ?, ?, 1)
            """, (ip, mac, attack_type, now, None, now))

        conn.commit()
        conn.close()
    except Exception as e:
        print("log_rogue_attack error:", e)

def detect_rogue_logic(trusted_macs, trusted_ips):
    current_time = datetime.now()
    trusted_macs = set(normalize_mac(m) for m in trusted_macs)

    with lock:
        arp_results = list(network_cache["arp"])

    arp_table     = {d["ip"]: normalize_mac(d["mac"]) for d in arp_results}
    rogue_devices = []
    ip_seen       = {}
    mac_seen      = {}

    for ip, mac in arp_table.items():
        if not mac or mac == "unknown":
            continue

        status_list = []

        if mac not in trusted_macs:
            status_list.append("Unauthorized Device")
            log_rogue(ip, mac, "Unauthorized")

        if ip in ip_mac_history:
            old_mac, last_time = ip_mac_history[ip]
            if old_mac != mac and (current_time - last_time).total_seconds() < 60:
                status_list.append("MAC Spoofing Detected")
                log_rogue(ip, mac, "MAC Spoofing")
        ip_mac_history[ip] = (mac, current_time)

        if mac in mac_ip_history:
            old_ip = mac_ip_history[mac]
            if old_ip != ip:
                status_list.append("IP Spoofing Detected")
                log_rogue(ip, mac, "IP Spoofing")
        mac_ip_history[mac] = ip

        if ip in ip_seen and ip_seen[ip] != mac:
            status_list.append("Duplicate IP Conflict")
            log_rogue(ip, mac, "Duplicate IP")
        ip_seen[ip] = mac

        if mac in mac_seen and mac_seen[mac] != ip:
            status_list.append("Duplicate MAC Detected")
            log_rogue(ip, mac, "Duplicate MAC")
        mac_seen[mac] = ip

        if status_list:
            status = " | ".join(status_list)
            logger.warning(f"ROGUE DETECTED: IP={ip}, MAC={mac}, TYPE={status}")
            if ip not in [r["ip"] for r in rogue_devices]:
                log_rogue_attack(ip, mac, status)
            rogue_devices.append({"ip": ip, "mac": mac, "status": status})

    return rogue_devices

# ROUTES — AUTH
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
            logger.info(f"LOGIN SUCCESS: {username}")
            session["user"] = username
            session["last_active"] = datetime.now().timestamp()
            session.permanent      = True
            return redirect("/")

        logger.warning(f"LOGIN FAILED: {username}")
        return render_template("login.html", error="Invalid Credentials")

    return render_template("login.html")

@app.route("/logout")
def logout():
    logger.info(f"LOGOUT: {session.get('user')}")
    session.clear()
    return redirect("/login")

# ROUTES — DASHBOARD
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

    current_time    = datetime.now()
    trusted_ips     = set(r[0] for r in trusted_rows)
    trusted_macs    = set(r[1] for r in trusted_rows)
    trusted_devices = [{"ip": r[0], "mac": r[1]} for r in trusted_rows]

    devices = []
    for row in rows:
        try:
            last_seen_time = datetime.strptime(str(row[8]), "%Y-%m-%d %H:%M:%S") if row[8] else current_time
        except Exception:
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
    all_ips        = arp_ips | db_ips | trusted_ip_set
    device_map     = {d["ip_address"]: d for d in devices}

    final_devices = []
    for ip in all_ips:
        if ip in arp_ips:
            status = "ONLINE"
        elif ip in device_map:
            status = device_map[ip]["status"]
        else:
            status = "OFFLINE"
        final_devices.append({"ip": ip, "status": status})

    unique        = {d["ip"]: d for d in final_devices}
    final_devices = list(unique.values())

    total_devices   = len(final_devices)
    online_devices  = sum(1 for d in final_devices if d["status"] == "ONLINE")
    offline_devices = total_devices - online_devices
    rogue_count     = len(set(d["ip"] for d in rogue_devices))
    trusted_count   = len(trusted_ips)

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

# ROUTES — AGENT API
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
        logger.info(f"Device data received: {ip_address} ({mac_address})")
        return jsonify({"status": "success"})

    except Exception as e:
        logger.error(f"Device API error: {str(e)}")
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

# ROUTES — DEVICE MANAGEMENT
@app.route("/approve-device", methods=["POST"])
def approve_device():
    ip  = request.form.get("ip")
    mac = normalize_mac(request.form.get("mac"))

    if not mac or mac == "unknown":
        return jsonify({"status": "error", "message": "Invalid MAC"})

    try:
        conn   = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM trusted_devices WHERE mac_address=?", (mac,))
        exists = cursor.fetchone()

        if not exists:
            cursor.execute("""
                INSERT INTO trusted_devices (ip_address, mac_address, device_name, location)
                VALUES (?, ?, ?, ?)
            """, (ip, mac, "Approved Device", "Network"))
        else:
            cursor.execute("UPDATE trusted_devices SET ip_address=? WHERE mac_address=?", (ip, mac))

        conn.commit()
        conn.close()
        logger.info(f"DEVICE APPROVED: IP={ip}, MAC={mac}")
        return jsonify({"status": "success"})

    except Exception as e:
        logger.info(f"Error : {e}")
        return jsonify({"status": "error", "message": str(e)})

@app.route("/disapprove-device", methods=["POST"])
def disapprove_device():
    try:
        mac    = request.form.get("mac")
        conn   = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM trusted_devices WHERE mac_address=?", (mac,))
        conn.commit()
        conn.close()
        logger.warning(f"DEVICE DISAPPROVED : MAC={mac}")
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# ROUTES — LIVE DATA
@app.route("/api/live-data")
def live_data():
    try:
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
            except Exception:
                last_seen_time = current_time

            status = "ONLINE" if (current_time - last_seen_time).total_seconds() <= 30 else "OFFLINE"

            devices.append({
                "hostname": row[1],
                "ip":       row[2],
                "cpu":      safe_float(row[5]),
                "ram":      safe_float(row[6]),
                "status":   status
            })

        trusted_list = [{"ip": r[0], "mac": r[1]} for r in trusted_rows]

        with lock:
            rogue = list(rogue_cache)
        with lock:
            arp_results = list(network_cache["arp"])
        arp_ips = set(d["ip"] for d in arp_results)

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
    except Exception as e:
        logger.error(f"Live data error: {str(e)}")
        return jsonify({"devices": [], "rogue": [], "trusted": [],
                        "total": 0, "online": 0, "offline": 0, "rogue_count": 0})

@app.before_request
def manage_session():
    session.permanent = True
    api_prefixes = ("/api/", "/scan-", "/stop-scan", "/detect-rogue",
                    "/approve-device", "/disapprove-device", "/generate-")
    if any(request.path.startswith(p) for p in api_prefixes):
        return

    if "user" in session:
        now         = datetime.now().timestamp()
        last_active = session.get("last_active", now)
        if now - last_active > 900:
            session.clear()
            return redirect("/login")
        session["last_active"] = now

# REPORT GENERATION
RPT_DARK_BLUE    = HexColor("#1a237e")
RPT_MED_BLUE     = HexColor("#283593")
RPT_ACCENT_BLUE  = HexColor("#1565c0")
RPT_LIGHT_BLUE   = HexColor("#e8eaf6")
RPT_PALE_BLUE    = HexColor("#f5f7ff")
RPT_GREEN        = HexColor("#1b5e20")
RPT_LIGHT_GREEN  = HexColor("#e8f5e9")
RPT_RED          = HexColor("#b71c1c")
RPT_LIGHT_RED    = HexColor("#ffebee")
RPT_ORANGE       = HexColor("#e65100")
RPT_LIGHT_ORANGE = HexColor("#fff3e0")
RPT_GREY         = HexColor("#616161")
RPT_LIGHT_GREY   = HexColor("#f5f5f5")
RPT_MID_GREY     = HexColor("#e0e0e0")
RPT_WHITE        = colors.white
RPT_BLACK        = colors.black

HEALTH_CONFIG = {
    "LOW RISK":    {"color": RPT_GREEN,  "bg": RPT_LIGHT_GREEN,  "label": "GOOD"},
    "MEDIUM RISK": {"color": RPT_ORANGE, "bg": RPT_LIGHT_ORANGE, "label": "CAUTION"},
    "HIGH RISK":   {"color": RPT_RED,    "bg": RPT_LIGHT_RED,    "label": "CRITICAL"},
    "UNKNOWN":     {"color": RPT_GREY,   "bg": RPT_LIGHT_GREY,   "label": "UNKNOWN"},
}

_HEADER_H = 82


def calculate_system_health(total, rogue):
    if total == 0:
        return "UNKNOWN"
    ratio = rogue / total
    if ratio > 0.3:
        return "HIGH RISK"
    elif ratio > 0.1:
        return "MEDIUM RISK"
    return "LOW RISK"

_rpt_ctx = {}

def _draw_watermark(canvas, doc):
    pw, ph = doc.pagesize
    canvas.saveState()
    canvas.translate(pw / 2, ph / 2)
    canvas.rotate(45)
    canvas.setFont("Helvetica-Bold", 80)
    canvas.setFillGray(0.92)
    canvas.drawCentredString(0, 0, "SCCSIMS")
    canvas.restoreState()

def _draw_page1_header(canvas, doc):
    pw, ph = doc.pagesize
    canvas.saveState()
    canvas.setFillColor(RPT_DARK_BLUE)
    canvas.rect(0, ph - _HEADER_H, pw, _HEADER_H, stroke=0, fill=1)
    canvas.setFillColor(HexColor("#ffd600"))
    canvas.rect(0, ph - _HEADER_H - 3, pw, 3, stroke=0, fill=1)
    logo_path  = _rpt_ctx.get("logo_path", "")
    logo_drawn = False
    if logo_path and os.path.exists(logo_path):
        try:
            from reportlab.lib.utils import ImageReader
            ir = ImageReader(logo_path)
            lw, lh = 52, 26
            ly = ph - _HEADER_H + (_HEADER_H - lh) / 2
            canvas.drawImage(ir, 16, ly, width=lw, height=lh,
                             preserveAspectRatio=True, mask="auto")
            logo_drawn = True
        except Exception:
            pass
    tx = 76 if logo_drawn else 16
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 19)
    canvas.drawString(tx, ph - _HEADER_H + 40, "SCCSIMS Security Report")
    canvas.setFont("Helvetica", 8.5)
    canvas.setFillColor(HexColor("#bbdefb"))
    canvas.drawString(
        tx, ph - _HEADER_H + 20,
        f"Generated: {_rpt_ctx.get('now_str', '')}   |   Operator: {_rpt_ctx.get('operator', 'admin')}"
    )
    canvas.restoreState()

def _draw_page_header(canvas, doc):
    pw, ph = doc.pagesize
    canvas.saveState()
    canvas.setFillColor(RPT_DARK_BLUE)
    canvas.rect(0, ph - 22, pw, 22, stroke=0, fill=1)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(16, ph - 15, "SCCSIMS Security Report")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(pw - 16, ph - 15, _rpt_ctx.get("now_str", ""))
    canvas.restoreState()

def _draw_footer(canvas, doc):
    pw, _ = doc.pagesize
    canvas.saveState()
    canvas.setStrokeColor(RPT_MID_GREY)
    canvas.setLineWidth(0.5)
    canvas.line(36, 30, pw - 36, 30)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(RPT_GREY)
    canvas.drawString(36, 14,
        "SCCSIMS — Smart Campus & Corporate Security Infrastructure Monitoring System")
    canvas.drawRightString(pw - 36, 14, f"Page {doc.page}")
    canvas.restoreState()

def _on_first_page(canvas, doc):
    _draw_watermark(canvas, doc)
    _draw_page1_header(canvas, doc)
    _draw_footer(canvas, doc)

def _on_later_pages(canvas, doc):
    _draw_watermark(canvas, doc)
    _draw_page_header(canvas, doc)
    _draw_footer(canvas, doc)

def _build_styles():
    base = getSampleStyleSheet()
    st   = {}
    st["section_heading"] = ParagraphStyle(
        "SH", parent=base["Normal"],
        fontName="Helvetica-Bold", fontSize=11,
        textColor=RPT_DARK_BLUE, spaceBefore=8, spaceAfter=3,
    )
    st["kpi_label"] = ParagraphStyle(
        "KL", parent=base["Normal"],
        fontName="Helvetica", fontSize=7.5,
        textColor=RPT_GREY, alignment=TA_CENTER, leading=9,
    )
    st["kpi_value"] = ParagraphStyle(
        "KVB", parent=base["Normal"],
        fontName="Helvetica-Bold", fontSize=18,
        textColor=RPT_DARK_BLUE, alignment=TA_CENTER, leading=22,
    )
    st["health_text"] = ParagraphStyle(
        "HT", parent=base["Normal"],
        fontName="Helvetica-Bold", fontSize=12,
        alignment=TA_CENTER, leading=16,
    )
    st["normal_sm"] = ParagraphStyle(
        "NS", parent=base["Normal"],
        fontName="Helvetica", fontSize=7.5,
        textColor=RPT_GREY, spaceAfter=2, leading=10,
    )
    st["note"] = ParagraphStyle(
        "NO", parent=base["Normal"],
        fontName="Helvetica-Oblique", fontSize=7.5,
        textColor=RPT_GREY, spaceBefore=3, leading=10,
    )
    st["wrap"] = ParagraphStyle(
        "WR", parent=base["Normal"],
        fontName="Helvetica", fontSize=7,
        textColor=RPT_BLACK, leading=9, wordWrap="LTR",
    )
    st["wrap_bold"] = ParagraphStyle(
        "WRB", parent=base["Normal"],
        fontName="Helvetica-Bold", fontSize=7,
        textColor=RPT_BLACK, leading=9, wordWrap="LTR",
    )
    st["wrap_red"] = ParagraphStyle(
        "WRR", parent=base["Normal"],
        fontName="Helvetica-Bold", fontSize=7,
        textColor=RPT_RED, leading=9, wordWrap="LTR",
    )
    st["wrap_green"] = ParagraphStyle(
        "WRG", parent=base["Normal"],
        fontName="Helvetica-Bold", fontSize=7,
        textColor=RPT_GREEN, leading=9, wordWrap="LTR",
    )
    return st

def _tbl_style(header_bg=None):
    if header_bg is None:
        header_bg = RPT_MED_BLUE
    return TableStyle([
        ("BACKGROUND",    (0, 0), (-1,  0), header_bg),
        ("TEXTCOLOR",     (0, 0), (-1,  0), RPT_WHITE),
        ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1,  0), 7.5),
        ("ALIGN",         (0, 0), (-1,  0), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1,  0), 6),
        ("BOTTOMPADDING", (0, 0), (-1,  0), 6),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 1), (-1, -1), 7),
        ("ALIGN",         (0, 1), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [RPT_WHITE, RPT_PALE_BLUE]),
        ("GRID",          (0, 0), (-1, -1), 0.35, HexColor("#c5cae9")),
        ("LINEBELOW",     (0, 0), (-1,  0), 1.5, RPT_DARK_BLUE),
    ])

def _section_bar(label, st):
    tbl = Table([[Paragraph(f"  {label}", st["section_heading"])]], colWidths=["100%"])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), RPT_LIGHT_BLUE),
        ("LINEBELOW",     (0, 0), (-1, -1), 2,   RPT_ACCENT_BLUE),
        ("LINEABOVE",     (0, 0), (-1, -1), 0.5, RPT_ACCENT_BLUE),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]))
    return tbl

def _cell(text, st, key="wrap", color=None):
    val = str(text) if (text is not None and str(text).strip() not in ("", "None")) else "—"
    if color:
        sty = ParagraphStyle(f"cc_{key}", parent=st[key], textColor=color)
    else:
        sty = st[key]
    return Paragraph(val, sty)

def _status_pill(status_str, st):
    s = (status_str or "").strip().upper()
    if s not in ("ONLINE", "OFFLINE"):
        s = "ONLINE"
    fg = "#1b5e20" if s == "ONLINE" else "#b71c1c"
    bg = "#c8e6c9" if s == "ONLINE" else "#ffcdd2"
    pill = ParagraphStyle(
        f"Pill{s}", parent=st["normal_sm"],
        fontName="Helvetica-Bold", fontSize=6.5,
        textColor=HexColor(fg), backColor=HexColor(bg),
        alignment=TA_CENTER, borderPad=2,
    )
    return Paragraph(s, pill)

def generate_graphs(online_count=0, offline_count=0, rogue_count=0, trusted_count=0):
    timestamps = analytics_history["timestamps"]
    cpu_data   = analytics_history["cpu_avg"]
    ram_data   = analytics_history.get("ram_avg", [])
    rogue_data = analytics_history["rogue_count"]
    total_data = analytics_history["total_devices"]
    tmpdir     = tempfile.gettempdir()

    def _ax_style(ax, title, xlabel, ylabel):
        ax.set_title(title, fontsize=10, fontweight="bold", color="#1a237e", pad=8)
        ax.set_xlabel(xlabel, fontsize=7.5, color="#616161")
        ax.set_ylabel(ylabel, fontsize=7.5, color="#616161")
        ax.tick_params(axis="both", labelsize=6.5, colors="#616161")
        for sp in ["top", "right"]:
            ax.spines[sp].set_visible(False)
        ax.spines["left"].set_color("#bdbdbd")
        ax.spines["bottom"].set_color("#bdbdbd")
        ax.set_facecolor("#fafafa")
        ax.grid(True, ls="--", lw=0.4, color="#e0e0e0", alpha=0.8)

    def _set_xticks(ax, xs, labels):
        step = max(1, len(xs) // 8)
        ax.set_xticks(xs[::step])
        ax.set_xticklabels(labels[::step], rotation=35, ha="right", fontsize=6.5)

    def _no_data_text(ax, msg="No data collected yet"):
        ax.text(0.5, 0.5, msg, ha="center", va="center",
                transform=ax.transAxes, color="#9e9e9e", fontsize=9)

    cpu_path = os.path.join(tmpdir, "sccsims_cpu.png")
    fig, ax = plt.subplots(figsize=(7.2, 2.8))
    fig.patch.set_facecolor("#ffffff")
    if timestamps and cpu_data:
        xs = np.arange(len(timestamps))
        ax.plot(xs, cpu_data, color="#1565c0", lw=2, marker="o", ms=3.5, zorder=3)
        ax.fill_between(xs, cpu_data, alpha=0.10, color="#1565c0")
        ax.axhspan(80, 105, alpha=0.06, color="red")
        ax.axhline(80, color="#e53935", lw=0.8, ls="--", alpha=0.55)
        ax.text(xs[0], 82, "High (80%)", fontsize=5.5, color="#e53935")
        ax.set_ylim(0, 105)
        _set_xticks(ax, xs, timestamps)
    else:
        _no_data_text(ax, "No CPU data collected yet")
    _ax_style(ax, "Average CPU Usage Trend (%)", "Time", "CPU %")
    plt.tight_layout(pad=1.1)
    plt.savefig(cpu_path, dpi=150, bbox_inches="tight", facecolor="#ffffff")
    plt.close()

    ram_path = os.path.join(tmpdir, "sccsims_ram.png")
    fig, ax = plt.subplots(figsize=(7.2, 2.8))
    fig.patch.set_facecolor("#ffffff")
    if timestamps and ram_data and any(v > 0 for v in ram_data):
        xs = np.arange(len(timestamps))
        ax.plot(xs, ram_data, color="#6a1b9a", lw=2, marker="D", ms=3.5, zorder=3)
        ax.fill_between(xs, ram_data, alpha=0.10, color="#6a1b9a")
        ax.axhspan(85, 105, alpha=0.06, color="red")
        ax.axhline(85, color="#e53935", lw=0.8, ls="--", alpha=0.55)
        ax.text(xs[0], 87, "High (85%)", fontsize=5.5, color="#e53935")
        ax.set_ylim(0, 105)
        _set_xticks(ax, xs, timestamps)
    else:
        _no_data_text(ax, "No RAM data collected yet")
    _ax_style(ax, "Average RAM Usage Trend (%)", "Time", "RAM %")
    plt.tight_layout(pad=1.1)
    plt.savefig(ram_path, dpi=150, bbox_inches="tight", facecolor="#ffffff")
    plt.close()

    rogue_path = os.path.join(tmpdir, "sccsims_rogue.png")
    fig, ax = plt.subplots(figsize=(7.2, 2.8))
    fig.patch.set_facecolor("#ffffff")
    if timestamps and rogue_data:
        xs = np.arange(len(timestamps))
        ax.plot(xs, rogue_data, color="#c62828", lw=2, marker="s", ms=3.5, zorder=3)
        ax.fill_between(xs, rogue_data, alpha=0.12, color="#c62828")
        ax.yaxis.get_major_locator().set_params(integer=True)
        _set_xticks(ax, xs, timestamps)
    else:
        _no_data_text(ax, "No rogue activity recorded")
    _ax_style(ax, "Rogue Device Activity Trend", "Time", "Rogue Count")
    plt.tight_layout(pad=1.1)
    plt.savefig(rogue_path, dpi=150, bbox_inches="tight", facecolor="#ffffff")
    plt.close()

    pie_path = os.path.join(tmpdir, "sccsims_pie.png")
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.4))
    fig.patch.set_facecolor("#ffffff")
    online_clean = max(0, online_count - rogue_count)
    p1 = [(online_clean, "Online",  "#43a047"),
          (offline_count,"Offline", "#78909c"),
          (rogue_count,  "Rogue",   "#e53935")]
    p1 = [(v, l, c) for v, l, c in p1 if v > 0]
    if p1:
        ws, _, ats = axes[0].pie(
            [x[0] for x in p1], labels=None,
            colors=[x[2] for x in p1],
            autopct="%1.1f%%", startangle=140,
            wedgeprops={"edgecolor": "white", "linewidth": 1.5},
            pctdistance=0.76,
        )
        for at in ats:
            at.set_fontsize(7.5); at.set_color("white"); at.set_fontweight("bold")
        axes[0].legend(ws, [x[1] for x in p1], loc="lower center",
                       bbox_to_anchor=(0.5, -0.22), ncol=3, fontsize=7, frameon=False)
    else:
        axes[0].text(0, 0, "No data", ha="center", va="center", color="#9e9e9e")
    axes[0].set_title("Device Status Distribution", fontsize=8.5,
                      fontweight="bold", color="#1a237e", pad=6)
    total_seen = online_count + offline_count
    unauth     = max(0, total_seen - trusted_count)
    p2 = [(min(trusted_count, total_seen), "Trusted",      "#1565c0"),
          (unauth,                          "Unauthorized", "#ef6c00")]
    p2 = [(v, l, c) for v, l, c in p2 if v > 0]
    if p2:
        ws2, _, ats2 = axes[1].pie(
            [x[0] for x in p2], labels=None,
            colors=[x[2] for x in p2],
            autopct="%1.1f%%", startangle=90,
            wedgeprops={"edgecolor": "white", "linewidth": 1.5},
            pctdistance=0.76,
        )
        for at in ats2:
            at.set_fontsize(7.5); at.set_color("white"); at.set_fontweight("bold")
        axes[1].legend(ws2, [x[1] for x in p2], loc="lower center",
                       bbox_to_anchor=(0.5, -0.22), ncol=2, fontsize=7, frameon=False)
    else:
        axes[1].text(0, 0, "No data", ha="center", va="center", color="#9e9e9e")
    axes[1].set_title("Trust Distribution", fontsize=8.5,
                      fontweight="bold", color="#1a237e", pad=6)
    plt.tight_layout(pad=1.4)
    plt.savefig(pie_path, dpi=150, bbox_inches="tight", facecolor="#ffffff")
    plt.close()

    combined_path = os.path.join(tmpdir, "sccsims_combined.png")
    fig, ax = plt.subplots(figsize=(7.2, 2.8))
    fig.patch.set_facecolor("#ffffff")
    if timestamps and total_data:
        xs = np.arange(len(timestamps))
        w  = 0.30
        b1 = ax.bar(xs - w / 2, total_data, w, label="Total", color="#90caf9", zorder=2)
        b2 = ax.bar(xs + w / 2, rogue_data, w, label="Rogue", color="#ef9a9a", zorder=2)
        for rect in list(b1) + list(b2):
            h = rect.get_height()
            if h > 0:
                ax.text(rect.get_x() + rect.get_width() / 2, h + 0.05,
                        str(int(h)), ha="center", va="bottom", fontsize=5.5, color="#424242")
        ax.yaxis.get_major_locator().set_params(integer=True)
        ax.legend(fontsize=7, frameon=False, loc="upper right")
        _set_xticks(ax, xs, timestamps)
    else:
        _no_data_text(ax, "Insufficient scan data")
    _ax_style(ax, "Network Overview — Total vs Rogue Devices", "Time", "Count")
    plt.tight_layout(pad=1.1)
    plt.savefig(combined_path, dpi=150, bbox_inches="tight", facecolor="#ffffff")
    plt.close()

    return cpu_path, ram_path, rogue_path, pie_path, combined_path

@app.route("/generate-report")
def generate_report():
    if "user" not in session:
        return redirect("/login")

    st     = _build_styles()
    buffer = BytesIO()
    TOP_MARGIN    = _HEADER_H + 8
    BOTTOM_MARGIN = 42

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=1.6 * cm,
        rightMargin=1.6 * cm,
        topMargin=TOP_MARGIN,
        bottomMargin=BOTTOM_MARGIN,
        title="SCCSIMS Security Report",
        author="SCCSIMS",
    )
    page_w = A4[0] - doc.leftMargin - doc.rightMargin
    elems  = []

    _rpt_ctx["now_str"]   = datetime.now().strftime("%A, %d %B %Y  •  %H:%M:%S")
    _rpt_ctx["operator"]  = session.get("user", "admin")
    _rpt_ctx["logo_path"] = "static/logo.png"

    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT hostname, ip_address, mac_address, os, cpu_usage, ram_usage, location, last_seen "
        "FROM devices"
    )
    db_devices = cursor.fetchall()
    cursor.execute("SELECT ip_address, mac_address, device_name, location FROM trusted_devices")
    trusted_rows = cursor.fetchall()
    cursor.execute("""
        SELECT ip, mac, attack_type, first_seen, last_seen
        FROM rogue_history
        ORDER BY datetime(last_seen) DESC
        LIMIT 20
    """)
    attacks = cursor.fetchall()
    conn.close()

    with lock:
        rogue_live  = list(rogue_cache)
        arp_results = list(network_cache["arp"])

    arp_ips      = set(d["ip"] for d in arp_results)
    trusted_macs = set(normalize_mac(r[1]) for r in trusted_rows)
    current_time = datetime.now()

    devices_enriched = []
    for row in db_devices:
        hostname, ip, mac, os_, cpu, ram, loc, last_seen = row
        mac_norm = normalize_mac(mac)
        try:
            ls_time = datetime.strptime(str(last_seen), "%Y-%m-%d %H:%M:%S")
        except Exception:
            ls_time = current_time
        if ip in arp_ips:
            status = "ONLINE"
        elif (current_time - ls_time).total_seconds() <= 30:
            status = "ONLINE"
        else:
            status = "OFFLINE"
        devices_enriched.append({
            "hostname":  hostname or "—",
            "ip":        ip or "—",
            "mac":       mac_norm,
            "os":        os_ or "—",
            "cpu":       safe_float(cpu),
            "ram":       safe_float(ram),
            "location":  loc or "—",
            "last_seen": last_seen or "—",
            "status":    status,
            "trusted":   mac_norm in trusted_macs,
            "monitored": True,
        })

    db_ips = set(d["ip"] for d in devices_enriched)
    for arp in arp_results:
        if arp["ip"] not in db_ips:
            mac_norm = normalize_mac(arp.get("mac", "unknown"))
            devices_enriched.append({
                "hostname":  "—",
                "ip":        arp["ip"],
                "mac":       mac_norm,
                "os":        "—",
                "status":    "ONLINE",
                "cpu":       None,
                "ram":       None,
                "location":  "—",
                "last_seen": "—",
                "trusted":   mac_norm in trusted_macs,
                "monitored": False,
            })

    online_count  = sum(1 for d in devices_enriched if d["status"] == "ONLINE")
    offline_count = sum(1 for d in devices_enriched if d["status"] == "OFFLINE")
    total_count   = len(devices_enriched)
    rogue_count   = len(set(r["ip"] for r in rogue_live))
    trusted_count = len(trusted_rows)
    unauthorized  = [d for d in devices_enriched if not d["trusted"]]

    health     = calculate_system_health(total_count, rogue_count)
    health_cfg = HEALTH_CONFIG.get(health, HEALTH_CONFIG["UNKNOWN"])

    cpu_path, ram_path, rogue_path, pie_path, combined_path = generate_graphs(
        online_count=online_count,
        offline_count=offline_count,
        rogue_count=rogue_count,
        trusted_count=trusted_count,
    )

    elems.append(Spacer(1, 6))
    h_sty = ParagraphStyle(
        "HBan", parent=st["health_text"],
        textColor=health_cfg["color"], backColor=health_cfg["bg"],
    )
    htbl = Table(
        [[Paragraph(f"System Health: {health}   [{health_cfg['label']}]", h_sty)]],
        colWidths=[page_w],
    )
    htbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), health_cfg["bg"]),
        ("LINEABOVE",     (0, 0), (-1, -1), 2.5, health_cfg["color"]),
        ("LINEBELOW",     (0, 0), (-1, -1), 2.5, health_cfg["color"]),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))
    elems.append(htbl)
    elems.append(Spacer(1, 12))

    kpi_defs = [
        ("Total Devices", str(total_count),       RPT_ACCENT_BLUE,     RPT_LIGHT_BLUE),
        ("Online",        str(online_count),       RPT_GREEN,           RPT_LIGHT_GREEN),
        ("Offline",       str(offline_count),      RPT_RED,             RPT_LIGHT_RED),
        ("Trusted",       str(trusted_count),      HexColor("#006064"), HexColor("#e0f7fa")),
        ("Unauthorized",  str(len(unauthorized)),  RPT_ORANGE,          RPT_LIGHT_ORANGE),
        ("Rogue Events",  str(rogue_count),        RPT_RED,             HexColor("#fce4ec")),
    ]
    card_w    = page_w / len(kpi_defs)
    kpi_cells = []
    for lbl, val, tc, bc in kpi_defs:
        vs = ParagraphStyle(f"KV_{lbl}", parent=st["kpi_value"], textColor=tc)
        card = Table(
            [[Paragraph(val, vs)], [Paragraph(lbl, st["kpi_label"])]],
            colWidths=[card_w - 6],
        )
        card.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), bc),
            ("TOPPADDING",    (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("LINEBELOW",     (0, 0), (-1, -1), 3, tc),
        ]))
        kpi_cells.append(card)

    kpi_row = Table([kpi_cells], colWidths=[card_w] * len(kpi_defs))
    kpi_row.setStyle(TableStyle([
        ("LEFTPADDING",  (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]))
    elems.append(kpi_row)
    elems.append(Spacer(1, 14))

    elems.append(_section_bar("Executive Summary", st))
    elems.append(Spacer(1, 5))
    sum_rows = [
        [_cell("Metric", st, "wrap_bold"),  _cell("Value", st, "wrap_bold"), _cell("Notes", st, "wrap_bold")],
        [_cell("Total Devices", st),        _cell(total_count, st, "wrap_bold"), _cell("ARP + agent reports", st)],
        [_cell("Online", st),               _cell(online_count, st, "wrap_bold", RPT_GREEN), _cell("Active in current ARP scan", st)],
        [_cell("Offline", st),              _cell(offline_count, st, "wrap_bold", RPT_RED), _cell("Timed-out since last scan", st)],
        [_cell("Trusted Devices", st),      _cell(trusted_count, st, "wrap_bold"), _cell("Manually approved MACs", st)],
        [_cell("Unauthorized Devices", st), _cell(len(unauthorized), st, "wrap_bold", RPT_ORANGE), _cell("MAC not in trusted list", st)],
        [_cell("Active Rogue Events", st),  _cell(rogue_count, st, "wrap_bold", RPT_RED), _cell("Current scan cycle", st)],
        [_cell("Attack Records (DB)", st),  _cell(len(attacks), st, "wrap_bold"), _cell("Cumulative history, last 20 shown", st)],
        [_cell("System Health", st),        _cell(health, st, "wrap_bold", health_cfg["color"]), _cell(f"Rogue ratio {rogue_count}/{max(total_count,1)}", st)],
    ]
    sum_tbl = Table(sum_rows, colWidths=[page_w*0.35, page_w*0.18, page_w*0.47])
    ts = _tbl_style()
    ts.add("ALIGN",    (1, 1), (1, -1), "CENTER")
    ts.add("ALIGN",    (2, 1), (2, -1), "LEFT")
    sum_tbl.setStyle(ts)
    elems.append(sum_tbl)

    elems.append(PageBreak())
    elems.append(_section_bar(f"All Devices  ({total_count} total)", st))
    elems.append(Spacer(1, 4))
    elems.append(Paragraph(
        "All devices found via ARP scan and agent reports.  "
        "<b>ONLINE</b> = seen in ARP.  <b>OFFLINE</b> = timed out.  "
        "<b>CPU/RAM = N/A</b> for ARP-only (unmonitored) devices.",
        st["note"]
    ))
    elems.append(Spacer(1, 5))

    dev_cw = [
        page_w * 0.038, page_w * 0.105, page_w * 0.095, page_w * 0.130,
        page_w * 0.075, page_w * 0.055, page_w * 0.055, page_w * 0.085,
        page_w * 0.150, page_w * 0.097, page_w * 0.115,
    ]
    dev_hdr  = ["#", "Hostname", "IP Address", "MAC Address",
                "OS", "CPU%", "RAM%", "Location", "Last Seen", "Status", "Agent"]
    dev_data = [[_cell(h, st, "wrap_bold") for h in dev_hdr]]
    for idx, d in enumerate(devices_enriched, 1):
        try:
            ls_disp = fmt_timestamp(d["last_seen"])
        except Exception:
            ls_disp = d["last_seen"]
        cpu_disp = f"{d['cpu']:.1f}" if d["cpu"] is not None else "N/A"
        ram_disp = f"{d['ram']:.1f}" if d["ram"] is not None else "N/A"
        mon_text = "Monitored" if d["monitored"] else "ARP only"
        dev_data.append([
            _cell(idx, st), _cell(d["hostname"], st), _cell(d["ip"], st),
            _cell(d["mac"], st), _cell(d["os"], st), _cell(cpu_disp, st),
            _cell(ram_disp, st), _cell(d["location"], st), _cell(ls_disp, st),
            _status_pill(d["status"], st), _cell(mon_text, st),
        ])
    dev_tbl = Table(dev_data, colWidths=dev_cw, repeatRows=1)
    dev_ts  = _tbl_style()
    for i, d in enumerate(devices_enriched, 1):
        bg = HexColor("#fff5f5") if d["status"] == "OFFLINE" else RPT_WHITE
        dev_ts.add("BACKGROUND", (0, i), (-2, i), bg)
    dev_tbl.setStyle(dev_ts)
    elems.append(dev_tbl)

    elems.append(PageBreak())
    elems.append(_section_bar(f"Trusted Devices  ({trusted_count})", st))
    elems.append(Spacer(1, 5))
    if trusted_rows:
        tr_cw   = [page_w*0.05, page_w*0.22, page_w*0.27, page_w*0.24, page_w*0.22]
        tr_data = [[_cell(h, st, "wrap_bold")
                    for h in ["#", "IP Address", "MAC Address", "Device Name", "Location"]]]
        for idx, r in enumerate(trusted_rows, 1):
            tr_data.append([
                _cell(idx, st), _cell(r[0], st), _cell(r[1], st),
                _cell(r[2] or "Approved Device", st), _cell(r[3], st),
            ])
        tr_tbl = Table(tr_data, colWidths=tr_cw, repeatRows=1)
        tr_tbl.setStyle(_tbl_style(HexColor("#00695c")))
        elems.append(tr_tbl)
    else:
        elems.append(Paragraph("No trusted devices registered.", st["note"]))

    elems.append(Spacer(1, 16))
    elems.append(_section_bar(f"Unauthorized Devices  ({len(unauthorized)})", st))
    elems.append(Spacer(1, 5))
    if unauthorized:
        ua_cw = [page_w*0.04, page_w*0.12, page_w*0.12,
                 page_w*0.20, page_w*0.09, page_w*0.16, page_w*0.12, page_w*0.15]
        ua_data = [[_cell(h, st, "wrap_bold")
                    for h in ["#", "Hostname", "IP Address", "MAC Address",
                               "OS", "Location", "Status", "Agent"]]]
        for idx, d in enumerate(unauthorized, 1):
            ua_data.append([
                _cell(idx, st), _cell(d["hostname"], st), _cell(d["ip"], st),
                _cell(d["mac"], st), _cell(d["os"], st), _cell(d["location"], st),
                _status_pill(d["status"], st),
                _cell("Monitored" if d["monitored"] else "ARP only", st),
            ])
        ua_tbl = Table(ua_data, colWidths=ua_cw, repeatRows=1)
        ua_ts  = _tbl_style(HexColor("#bf360c"))
        for i in range(1, len(ua_data)):
            bg = RPT_LIGHT_ORANGE if i % 2 == 1 else RPT_WHITE
            ua_ts.add("BACKGROUND", (0, i), (-2, i), bg)
        ua_tbl.setStyle(ua_ts)
        elems.append(ua_tbl)
    else:
        elems.append(Paragraph("All observed MACs are present in the trusted list.", st["note"]))

    elems.append(PageBreak())
    elems.append(_section_bar(f"Attack & Rogue Event History  (last {len(attacks)})", st))
    elems.append(Spacer(1, 5))
    if attacks:
        atk_cw = [
            page_w * 0.040, page_w * 0.115, page_w * 0.160,
            page_w * 0.315, page_w * 0.185, page_w * 0.185,
        ]
        atk_data = [[_cell(h, st, "wrap_bold")
                     for h in ["#", "IP Address", "MAC Address", "Attack Type",
                                "First Seen", "Last Seen"]]]
        for idx, a in enumerate(attacks, 1):
            atype   = str(a[2] or "—")
            is_bad  = any(k in atype.lower() for k in ("spoofing", "duplicate", "conflict"))
            atype_p = _cell(atype, st, "wrap_red" if is_bad else "wrap")
            atk_data.append([
                _cell(idx, st), _cell(a[0], st), _cell(a[1], st), atype_p,
                _cell(fmt_timestamp(a[3]) if a[3] else "—", st),
                _cell(fmt_timestamp(a[4]) if a[4] else "—", st),
            ])
        atk_tbl = Table(atk_data, colWidths=atk_cw, repeatRows=1)
        atk_ts  = _tbl_style(RPT_DARK_BLUE)
        for i, a in enumerate(attacks, 1):
            if any(k in str(a[2] or "").lower() for k in ("spoofing", "duplicate", "conflict")):
                atk_ts.add("BACKGROUND", (0, i), (-1, i), HexColor("#ffebee"))
        atk_tbl.setStyle(atk_ts)
        elems.append(atk_tbl)
    else:
        elems.append(Paragraph("No attack records found in the database.", st["note"]))

    elems.append(PageBreak())
    elems.append(_section_bar("Network Analytics & Trend Graphs", st))
    elems.append(Spacer(1, 8))

    cap_sty = ParagraphStyle(
        "Cap", parent=st["note"],
        alignment=TA_CENTER, fontSize=7.5, spaceBefore=3,
    )

    def _graph_block(img_path, caption, height=2.5 * inch):
        items = []
        if img_path and os.path.exists(img_path):
            frame = Table(
                [[Image(img_path, width=page_w - 18, height=height)]],
                colWidths=[page_w],
            )
            frame.setStyle(TableStyle([
                ("BOX",           (0, 0), (-1, -1), 0.7, HexColor("#c5cae9")),
                ("BACKGROUND",    (0, 0), (-1, -1), RPT_PALE_BLUE),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 9),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 9),
            ]))
            items.append(frame)
        else:
            items.append(Paragraph("Graph not available.", st["note"]))
        items.append(Paragraph(caption, cap_sty))
        items.append(Spacer(1, 10))
        return items

    elems.extend(_graph_block(cpu_path, "Figure 1 — Average CPU usage across agent-monitored devices (last 20 scan cycles)."))
    elems.extend(_graph_block(ram_path, "Figure 2 — Average RAM usage across agent-monitored devices (last 20 scan cycles)."))
    elems.extend(_graph_block(rogue_path, "Figure 3 — Rogue device count per cycle. Spikes indicate new unauthorized MACs."))
    elems.extend(_graph_block(pie_path,
        "Figure 4 — Left: Device status breakdown (Online/Offline/Rogue).  "
        "Right: Trust breakdown (Trusted vs Unauthorized).", height=3.0 * inch))
    elems.extend(_graph_block(combined_path, "Figure 5 — Total devices vs rogue count across the last 20 scan cycles."))

    doc.build(elems, onFirstPage=_on_first_page, onLaterPages=_on_later_pages)
    buffer.seek(0)
    fname = f"SCCSIMS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        buffer,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )

# ROUTES — ANALYTICS & ATTACKER
@app.route("/api/analytics")
def analytics():
    return jsonify(analytics_history)

@app.route("/api/last-attacker")
def last_attacker():
    try:
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
    except Exception as e:
        return jsonify({"ip": None, "message": str(e)})

# ROUTES — NETWORK SCAN
@app.route("/scan-network")
def scan_network_route():
    return jsonify(scan_network())

@app.route("/scan-arp")
def scan_arp():
    return jsonify(scan_network_arp())

@app.route("/detect-rogue")
def detect_rogue_devices():
    try:
        conn   = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address, mac_address FROM trusted_devices")
        trusted_rows = cursor.fetchall()
        conn.close()
        trusted_ips  = set(r[0] for r in trusted_rows)
        trusted_macs = set(r[1] for r in trusted_rows)
        return jsonify({"rogue_devices": detect_rogue_logic(trusted_macs, trusted_ips)})
    except Exception as e:
        return jsonify({"rogue_devices": [], "error": str(e)})

# ROUTES — PORT SCANNER
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
        except Exception:
            pass
    return open_ports

def scan_single_port(ip, port, timeout):
    try:
        sock   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
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
    except Exception:
        return "data: error\n\n"

    if end - start > 5000:
        return "data: Range too large\n\n"

    ports   = list(range(start, end + 1))
    timeout = {"aggressive": 0.3, "stealth": 2}.get(speed, 0.8)

    def generate():
        scan_control["stop"] = False
        open_ports = []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(scan_single_port, ip, p, timeout)
                       for p in ports if not scan_control["stop"]]

            for future in as_completed(futures):
                if scan_control["stop"]:
                    break
                result = future.result()
                if result:
                    open_ports.append(result)
                    yield f"data: {result}\n\n"

        save_scan_history(ip, open_ports)
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
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            results = executor.map(scan_tcp, ports)

        return jsonify({"ip": ip, "open_ports": sorted(p for p in results if p)})
    except Exception as e:
        return jsonify({"error": "scan failed", "open_ports": []})

def save_scan_history(ip, ports):
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Normalize ports (handle int OR dict)
        clean_ports = []
        for p in ports:
            if isinstance(p, dict):
                clean_ports.append(p.get("port"))
            else:
                clean_ports.append(p)

        clean_ports = [p for p in clean_ports if p is not None]

        high_risk_ports = [p for p in clean_ports if p in [21, 23, 445, 3389, 4444]]

        cursor.execute("""
            INSERT INTO scan_history (ip, ports, high_risk, time)
            VALUES (?, ?, ?, ?)
        """, (
            ip,
            ",".join(str(p) for p in clean_ports),
            len(high_risk_ports),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        conn.commit()
        conn.close()

    except Exception as e:
        print("save_scan_history ERROR:", e)

@app.route("/stop-scan")
def stop_scan():
    scan_control["stop"] = True
    return jsonify({"status": "stopped"})

ROGUE_LOG_COOLDOWN_SECONDS = 60

def log_rogue(ip, mac, attack_type):
    try:
        conn   = get_db()
        cursor = conn.cursor()
        now    = datetime.now()

        cursor.execute("""
            SELECT detected_at FROM rogue_logs
            WHERE ip=? AND mac=? AND attack_type=?
            ORDER BY id DESC LIMIT 1
        """, (ip, mac, attack_type))

        last_row = cursor.fetchone()
        if last_row:
            try:
                last_time = datetime.strptime(last_row[0], "%Y-%m-%d %H:%M:%S")
                if (now - last_time).total_seconds() < ROGUE_LOG_COOLDOWN_SECONDS:
                    conn.close()
                    return  # Skip — duplicate within cooldown window
            except Exception:
                pass

        cursor.execute("""
            INSERT INTO rogue_logs (ip, mac, attack_type, detected_at)
            VALUES (?, ?, ?, ?)
        """, (ip, mac, attack_type, now.strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
    except Exception as e:
        print("log_rogue error:", e)

@app.route("/generate-port-report", methods=["POST"])
def generate_port_report():
    try:
        data      = request.get_json()
        ip        = data.get("ip")
        ports     = data.get("ports", [])
        timestamp = data.get("timestamp")

        buffer = io.BytesIO()
        doc    = SimpleDocTemplate(buffer)
        styles = getSampleStyleSheet()
        content = []

        content.append(Paragraph("Port Scan Security Report", styles['Title']))
        content.append(Spacer(1, 10))
        content.append(Paragraph(f"<b>Target IP:</b> {ip}", styles['Normal']))
        content.append(Paragraph(f"<b>Scan Time:</b> {timestamp}", styles['Normal']))
        content.append(Spacer(1, 15))

        table_data = [["Port", "Service", "Risk Level"]]
        high_count = 0
        for p in ports:
            port    = p.get("port")
            service = p.get("service")
            risk    = p.get("risk")
            if risk == "HIGH":
                high_count += 1
            table_data.append([str(port), service, risk])

        table = Table(table_data)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("ALIGN",      (0, 0), (-1,-1), "CENTER"),
            ("GRID",       (0, 0), (-1,-1), 1, colors.black),
        ]))
        content.append(table)
        content.append(Spacer(1, 15))

        if high_count > 0:
            summary = f"<font color='red'><b>HIGH RISK DETECTED: {high_count} critical ports open!</b></font>"
        else:
            summary = "<font color='green'><b>System appears secure (no critical ports)</b></font>"
        content.append(Paragraph(summary, styles['Normal']))

        doc.build(content)
        buffer.seek(0)

        try:
            conn   = get_db()
            cursor = conn.cursor()
            high_risk = sum(1 for p in ports if p.get("risk") == "HIGH")
            cursor.execute("""
                INSERT INTO scan_history (ip, ports, high_risk, time)
                VALUES (?, ?, ?, ?)
            """, (
                ip,
                ",".join(str(p.get("port")) for p in ports),
                high_risk,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print("generate_port_report DB error:", e)

        return send_file(
            buffer,
            as_attachment=True,
            download_name="Port_Scan_Report.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/scan-history")
def scan_history():
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT ip, ports, high_risk, time
            FROM scan_history
            ORDER BY id DESC
            LIMIT 50
        """)

        rows = cursor.fetchall()
        conn.close()

        data = []

        for r in rows:
            ports_str = r[1] if r[1] else ""

            try:
                port_list = [p.strip() for p in ports_str.split(",") if p.strip()]
            except:
                port_list = []

            data.append({
                "ip": r[0],
                "ports": ports_str,
                "port_count": len(port_list),
                "high_risk": r[2] if r[2] else 0,
                "time": r[3] if r[3] else "-"
            })

        return jsonify(data)


    except Exception as e:
        print("\nFULL ERROR TRACE:")
        traceback.print_exc()
        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500

@app.route("/api/rogue-logs")
def get_rogue_logs():
    try:
        conn   = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rogue_logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT,
                mac         TEXT,
                attack_type TEXT,
                detected_at TEXT
            )
        """)
        cursor.execute("SELECT * FROM rogue_logs ORDER BY id DESC LIMIT 50")
        rows = cursor.fetchall()
        conn.commit()
        conn.close()
        return jsonify([{
            "ip":   r[1],
            "mac":  r[2],
            "type": r[3],
            "time": r[4]
        } for r in rows])
    except Exception as e:
        print("get_rogue_logs error:", e)
        return jsonify({"error": str(e)}), 500

@app.route("/logs")
def view_logs():
    try:
        with open(LOG_FILE, "r") as f:
            logs = f.readlines()
        return "<br>".join(logs[::-1])
    except Exception as e:
        return f"Error reading logs: {str(e)}"

# STARTUP
if __name__ == "__main__":
    init_db()
    scanner_thread = threading.Thread(target=safe_background, daemon=True)
    scanner_thread.start()
    app.run(host="0.0.0.0", port=5000, debug=True,
            use_reloader=False, threaded=True)