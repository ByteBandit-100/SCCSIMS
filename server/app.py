import os
import socket
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from io import BytesIO

import matplotlib
from flask import Flask, request, jsonify, session, redirect, render_template, Response, stream_with_context
from werkzeug.security import generate_password_hash, check_password_hash

from arp_scanner import scan_network_arp
from network_scanner import scan_network

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import tempfile

# ─────────────────────────────────────────────
# REPORTLAB IMPORTS (expanded for professional report)
# ─────────────────────────────────────────────
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, PageBreak
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4

app = Flask(__name__)
app.config.update({
    "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SAMESITE": "Lax",
    "SESSION_COOKIE_SECURE": False,  # True if HTTPS
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

                timestamp = datetime.now().strftime("%H:%M:%S")

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

        if mac not in trusted_macs:
            status_list.append("Unauthorized Device")

        if ip in ip_mac_history:
            old_mac, last_time = ip_mac_history[ip]
            if old_mac != mac and (current_time - last_time).total_seconds() < 60:
                status_list.append("⚠ MAC Spoofing Detected")
        ip_mac_history[ip] = (mac, current_time)

        if mac in mac_ip_history:
            old_ip = mac_ip_history[mac]
            if old_ip != ip:
                status_list.append("⚠ IP Spoofing Detected")
        mac_ip_history[mac] = ip

        if ip in ip_seen and ip_seen[ip] != mac:
            status_list.append("⚠ Duplicate IP Conflict")
        ip_seen[ip] = mac

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
            session["last_active"] = datetime.now().timestamp()
            session.permanent = True
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
# ROUTES — LIVE DATA
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


# ═══════════════════════════════════════════════════════════════════════════════
# ██████████████████  REPORT GENERATION — FULLY IMPROVED  ██████████████████████
# ═══════════════════════════════════════════════════════════════════════════════

# ── Report colour palette ──────────────────────────────────────────────────────
RPT_DARK_BLUE   = HexColor("#1a237e")
RPT_MED_BLUE    = HexColor("#283593")
RPT_ACCENT_BLUE = HexColor("#1565c0")
RPT_LIGHT_BLUE  = HexColor("#e8eaf6")
RPT_PALE_BLUE   = HexColor("#f5f7ff")
RPT_GREEN       = HexColor("#1b5e20")
RPT_LIGHT_GREEN = HexColor("#e8f5e9")
RPT_RED         = HexColor("#b71c1c")
RPT_LIGHT_RED   = HexColor("#ffebee")
RPT_ORANGE      = HexColor("#e65100")
RPT_LIGHT_ORANGE= HexColor("#fff3e0")
RPT_GREY        = HexColor("#616161")
RPT_LIGHT_GREY  = HexColor("#f5f5f5")
RPT_MID_GREY    = HexColor("#e0e0e0")
RPT_WHITE       = colors.white
RPT_BLACK       = colors.black

# ── Health-level config ────────────────────────────────────────────────────────
HEALTH_CONFIG = {
    "LOW RISK":    {"color": RPT_GREEN,  "bg": RPT_LIGHT_GREEN,  "icon": "✔"},
    "MEDIUM RISK": {"color": RPT_ORANGE, "bg": RPT_LIGHT_ORANGE, "icon": "⚠"},
    "HIGH RISK":   {"color": RPT_RED,    "bg": RPT_LIGHT_RED,    "icon": "✖"},
    "UNKNOWN":     {"color": RPT_GREY,   "bg": RPT_LIGHT_GREY,   "icon": "?"},
}


def calculate_system_health(total, rogue):
    """Return health string based on rogue-to-total ratio."""
    if total == 0:
        return "UNKNOWN"
    ratio = rogue / total
    if ratio > 0.3:
        return "HIGH RISK"
    elif ratio > 0.1:
        return "MEDIUM RISK"
    return "LOW RISK"


# ── Diagonal watermark ─────────────────────────────────────────────────────────
def add_watermark(canvas, doc):
    """Render a diagonal 'SCCSIMS' watermark across every page."""
    canvas.saveState()
    page_w, page_h = doc.pagesize
    canvas.translate(page_w / 2, page_h / 2)
    canvas.rotate(45)
    canvas.setFont("Helvetica-Bold", 80)
    canvas.setFillGray(0.90)          # very light — won't compete with content
    canvas.drawCentredString(0, 0, "SCCSIMS")
    canvas.restoreState()


# ── Custom first-page callback (header stripe + watermark) ────────────────────
def _on_first_page(canvas, doc):
    add_watermark(canvas, doc)
    _draw_header_stripe(canvas, doc)


def _on_later_pages(canvas, doc):
    add_watermark(canvas, doc)
    _draw_footer(canvas, doc)


def _draw_header_stripe(canvas, doc):
    """Paint a dark-blue top stripe with a subtle accent line on page 1."""
    page_w, page_h = doc.pagesize
    canvas.saveState()
    canvas.setFillColor(RPT_DARK_BLUE)
    canvas.rect(0, page_h - 72, page_w, 72, stroke=0, fill=1)
    canvas.setFillColor(HexColor("#ffd600"))   # amber accent
    canvas.rect(0, page_h - 75, page_w, 3, stroke=0, fill=1)
    canvas.restoreState()


def _draw_footer(canvas, doc):
    """Page number footer on every page except the first."""
    page_w, _ = doc.pagesize
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(RPT_GREY)
    canvas.drawCentredString(page_w / 2, 20, f"SCCSIMS Security Report  •  Page {doc.page}")
    canvas.setStrokeColor(RPT_MID_GREY)
    canvas.line(40, 30, page_w - 40, 30)
    canvas.restoreState()


# ── Graph generation ───────────────────────────────────────────────────────────
def generate_graphs(online_count=0, offline_count=0, rogue_count=0, trusted_count=0):
    """
    Generate four analytics graphs and return their file paths.

    Returns
    -------
    cpu_path, rogue_path, pie_path, combined_path
    """

    timestamps  = analytics_history["timestamps"]
    cpu_data    = analytics_history["cpu_avg"]
    rogue_data  = analytics_history["rogue_count"]
    total_data  = analytics_history["total_devices"]

    # ── helper: apply consistent style ──────────────────────────────────────
    def _style_axes(ax, title, xlabel, ylabel):
        ax.set_title(title, fontsize=11, fontweight="bold", color="#1a237e", pad=10)
        ax.set_xlabel(xlabel, fontsize=8, color="#616161")
        ax.set_ylabel(ylabel, fontsize=8, color="#616161")
        ax.tick_params(axis="both", labelsize=7, colors="#616161")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_color("#bdbdbd")
        ax.spines["bottom"].set_color("#bdbdbd")
        ax.set_facecolor("#fafafa")
        ax.grid(True, linestyle="--", linewidth=0.5, color="#e0e0e0", alpha=0.8)

    tmpdir = tempfile.gettempdir()

    # ── 1. CPU Usage Trend ───────────────────────────────────────────────────
    cpu_path = os.path.join(tmpdir, "sccsims_cpu.png")
    fig, ax = plt.subplots(figsize=(7.5, 3))
    fig.patch.set_facecolor("#ffffff")
    if timestamps and cpu_data:
        xs = list(range(len(timestamps)))
        ax.plot(xs, cpu_data, color="#1565c0", linewidth=2, marker="o",
                markersize=4, zorder=3)
        ax.fill_between(xs, cpu_data, alpha=0.12, color="#1565c0")
        step = max(1, len(timestamps) // 8)
        ax.set_xticks(xs[::step])
        ax.set_xticklabels(timestamps[::step], rotation=35, ha="right", fontsize=7)
        ax.set_ylim(0, 105)
        # highlight danger zone
        ax.axhspan(80, 105, alpha=0.06, color="red")
        ax.axhline(80, color="#e53935", linewidth=0.8, linestyle="--", alpha=0.6)
        ax.text(0, 81, "High  ", fontsize=6, color="#e53935", va="bottom", ha="left")
    else:
        ax.text(0.5, 0.5, "Insufficient data", ha="center", va="center",
                transform=ax.transAxes, color="#9e9e9e", fontsize=10)
    _style_axes(ax, "CPU Usage Trend (%)", "Time", "CPU %")
    plt.tight_layout(pad=1.2)
    plt.savefig(cpu_path, dpi=150, bbox_inches="tight", facecolor="#ffffff")
    plt.close()

    # ── 2. Rogue Activity Trend ──────────────────────────────────────────────
    rogue_path = os.path.join(tmpdir, "sccsims_rogue.png")
    fig, ax = plt.subplots(figsize=(7.5, 3))
    fig.patch.set_facecolor("#ffffff")
    if timestamps and rogue_data:
        xs = list(range(len(timestamps)))
        ax.plot(xs, rogue_data, color="#c62828", linewidth=2, marker="s",
                markersize=4, zorder=3)
        ax.fill_between(xs, rogue_data, alpha=0.12, color="#c62828")
        step = max(1, len(timestamps) // 8)
        ax.set_xticks(xs[::step])
        ax.set_xticklabels(timestamps[::step], rotation=35, ha="right", fontsize=7)
        ax.yaxis.get_major_locator().set_params(integer=True)
    else:
        ax.text(0.5, 0.5, "No rogue activity recorded", ha="center", va="center",
                transform=ax.transAxes, color="#9e9e9e", fontsize=10)
    _style_axes(ax, "Rogue Device Activity Trend", "Time", "Rogue Count")
    plt.tight_layout(pad=1.2)
    plt.savefig(rogue_path, dpi=150, bbox_inches="tight", facecolor="#ffffff")
    plt.close()

    # ── 3. Device Distribution Pie Chart ────────────────────────────────────
    pie_path = os.path.join(tmpdir, "sccsims_pie.png")
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.5))
    fig.patch.set_facecolor("#ffffff")

    # Pie 1 — Online / Offline / Rogue
    online_clean  = max(0, online_count - rogue_count)
    pie1_vals  = [online_clean, offline_count, rogue_count]
    pie1_labels= ["Online", "Offline", "Rogue"]
    pie1_colors= ["#43a047", "#78909c", "#e53935"]
    pie1_vals_f = [v for v in pie1_vals if v > 0]
    pie1_labels_f = [pie1_labels[i] for i, v in enumerate(pie1_vals) if v > 0]
    pie1_colors_f = [pie1_colors[i] for i, v in enumerate(pie1_vals) if v > 0]

    if sum(pie1_vals_f) > 0:
        wedges, texts, autotexts = axes[0].pie(
            pie1_vals_f, labels=None,
            colors=pie1_colors_f,
            autopct="%1.1f%%", startangle=140,
            wedgeprops={"edgecolor": "white", "linewidth": 1.5},
            pctdistance=0.78
        )
        for at in autotexts:
            at.set_fontsize(8)
            at.set_color("white")
            at.set_fontweight("bold")
        axes[0].legend(wedges, pie1_labels_f, loc="lower center",
                       bbox_to_anchor=(0.5, -0.18), ncol=3, fontsize=7,
                       frameon=False)
    else:
        axes[0].text(0, 0, "No data", ha="center", va="center", color="#9e9e9e")
    axes[0].set_title("Device Status Distribution", fontsize=9, fontweight="bold",
                      color="#1a237e", pad=8)

    # Pie 2 — Trusted vs Unauthorized
    unauth = max(0, (online_count + offline_count) - trusted_count)
    pie2_vals  = [trusted_count, unauth]
    pie2_labels= ["Trusted", "Unauthorized"]
    pie2_colors= ["#1565c0", "#ef6c00"]
    pie2_vals_f = [v for v in pie2_vals if v > 0]
    pie2_labels_f = [pie2_labels[i] for i, v in enumerate(pie2_vals) if v > 0]
    pie2_colors_f = [pie2_colors[i] for i, v in enumerate(pie2_vals) if v > 0]

    if sum(pie2_vals_f) > 0:
        wedges2, texts2, autotexts2 = axes[1].pie(
            pie2_vals_f, labels=None,
            colors=pie2_colors_f,
            autopct="%1.1f%%", startangle=90,
            wedgeprops={"edgecolor": "white", "linewidth": 1.5},
            pctdistance=0.78
        )
        for at in autotexts2:
            at.set_fontsize(8)
            at.set_color("white")
            at.set_fontweight("bold")
        axes[1].legend(wedges2, pie2_labels_f, loc="lower center",
                       bbox_to_anchor=(0.5, -0.18), ncol=2, fontsize=7,
                       frameon=False)
    else:
        axes[1].text(0, 0, "No data", ha="center", va="center", color="#9e9e9e")
    axes[1].set_title("Trust Distribution", fontsize=9, fontweight="bold",
                      color="#1a237e", pad=8)

    plt.tight_layout(pad=1.5)
    plt.savefig(pie_path, dpi=150, bbox_inches="tight", facecolor="#ffffff")
    plt.close()

    # ── 4. Combined Timeline Bar Chart (total / online / rogue stacked) ──────
    combined_path = os.path.join(tmpdir, "sccsims_combined.png")
    fig, ax = plt.subplots(figsize=(7.5, 3))
    fig.patch.set_facecolor("#ffffff")
    if timestamps and total_data:
        xs   = np.arange(len(timestamps))
        w    = 0.28
        step = max(1, len(timestamps) // 8)

        bar_total  = ax.bar(xs - w, total_data,  w*0.9, label="Total",  color="#90caf9", zorder=2)
        bar_rogue  = ax.bar(xs,     rogue_data,  w*0.9, label="Rogue",  color="#ef9a9a", zorder=2)

        # Add value labels on bars
        for rect in list(bar_total) + list(bar_rogue):
            h = rect.get_height()
            if h > 0:
                ax.text(rect.get_x() + rect.get_width() / 2, h + 0.1,
                        str(int(h)), ha="center", va="bottom", fontsize=6, color="#424242")

        ax.set_xticks(xs[::step])
        ax.set_xticklabels(timestamps[::step], rotation=35, ha="right", fontsize=7)
        ax.yaxis.get_major_locator().set_params(integer=True)
        ax.legend(fontsize=7, frameon=False)
    else:
        ax.text(0.5, 0.5, "Insufficient data", ha="center", va="center",
                transform=ax.transAxes, color="#9e9e9e", fontsize=10)
    _style_axes(ax, "Network Activity Overview (Total vs Rogue)", "Time", "Count")
    plt.tight_layout(pad=1.2)
    plt.savefig(combined_path, dpi=150, bbox_inches="tight", facecolor="#ffffff")
    plt.close()

    return cpu_path, rogue_path, pie_path, combined_path


# ── Report helper — build custom styles ───────────────────────────────────────
def _build_styles():
    base = getSampleStyleSheet()
    styles = {}

    styles["report_title"] = ParagraphStyle(
        "ReportTitle",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=22,
        textColor=RPT_WHITE,
        alignment=TA_CENTER,
        spaceAfter=2,
        leading=26,
    )
    styles["report_subtitle"] = ParagraphStyle(
        "ReportSubtitle",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=10,
        textColor=HexColor("#bbdefb"),
        alignment=TA_CENTER,
        spaceAfter=4,
    )
    styles["section_heading"] = ParagraphStyle(
        "SectionHeading",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        textColor=RPT_DARK_BLUE,
        spaceBefore=14,
        spaceAfter=5,
        borderPad=4,
    )
    styles["kpi_label"] = ParagraphStyle(
        "KpiLabel",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=8,
        textColor=RPT_GREY,
        alignment=TA_CENTER,
        leading=10,
    )
    styles["kpi_value"] = ParagraphStyle(
        "KpiValue",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        textColor=RPT_DARK_BLUE,
        alignment=TA_CENTER,
        leading=24,
    )
    styles["health_text"] = ParagraphStyle(
        "HealthText",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        alignment=TA_CENTER,
        leading=18,
    )
    styles["normal_sm"] = ParagraphStyle(
        "NormalSm",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=8,
        textColor=RPT_GREY,
        spaceAfter=2,
    )
    styles["note"] = ParagraphStyle(
        "Note",
        parent=base["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=7.5,
        textColor=RPT_GREY,
        spaceBefore=4,
    )

    return styles


# ── Table style factories ──────────────────────────────────────────────────────
def _header_table_style(header_bg=None):
    if header_bg is None:
        header_bg = RPT_MED_BLUE
    return TableStyle([
        # Header row
        ("BACKGROUND",   (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR",    (0, 0), (-1, 0), RPT_WHITE),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0), 8),
        ("ALIGN",        (0, 0), (-1, 0), "CENTER"),
        ("BOTTOMPADDING",(0, 0), (-1, 0), 7),
        ("TOPPADDING",   (0, 0), (-1, 0), 7),
        # Data rows
        ("FONTNAME",     (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",     (0, 1), (-1, -1), 7.5),
        ("ALIGN",        (0, 1), (-1, -1), "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",   (0, 1), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 1), (-1, -1), 5),
        # Alternating rows
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [RPT_WHITE, RPT_PALE_BLUE]),
        # Grid
        ("GRID",         (0, 0), (-1, -1), 0.4, HexColor("#c5cae9")),
        ("LINEBELOW",    (0, 0), (-1, 0), 1.2, RPT_DARK_BLUE),
        ("LINEABOVE",    (0, 0), (-1, 0), 1.2, RPT_DARK_BLUE),
        ("ROUNDEDCORNERS", [3]),
    ])


def _section_divider(label, st):
    """Return a tinted heading bar element."""
    tbl = Table([[Paragraph(f"  {label}", st["section_heading"])]], colWidths=["100%"])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), RPT_LIGHT_BLUE),
        ("LINEBELOW",     (0, 0), (-1, -1), 2, RPT_ACCENT_BLUE),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return tbl


# ── Status pill helper ─────────────────────────────────────────────────────────
def _status_pill(status_str, st):
    """Return a coloured Paragraph acting as a status badge."""
    s = (status_str or "").upper()
    if s == "ONLINE":
        color = "#1b5e20"
        bg    = "#c8e6c9"
    elif s == "OFFLINE":
        color = "#b71c1c"
        bg    = "#ffcdd2"
    else:
        color = "#e65100"
        bg    = "#ffe0b2"

    pill_style = ParagraphStyle(
        "Pill",
        parent=st["normal_sm"],
        fontName="Helvetica-Bold",
        fontSize=7,
        textColor=HexColor(color),
        backColor=HexColor(bg),
        alignment=TA_CENTER,
        borderRadius=4,
        borderPad=3,
    )
    return Paragraph(s, pill_style)

@app.before_request
def manage_session():
    session.permanent = True

    if "user" in session:
        now = datetime.now().timestamp()

        last_active = session.get("last_active", now)

        # 15 min timeout
        if now - last_active > 900:
            session.clear()
            return redirect("/login")

        session["last_active"] = now

# ── Main report route ──────────────────────────────────────────────────────────
@app.route("/generate-report")
def generate_report():
    if "user" not in session:
        return redirect("/login")

    st      = _build_styles()
    buffer  = BytesIO()
    doc     = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=1.8 * cm,
        rightMargin=1.8 * cm,
        topMargin=2.6 * cm,
        bottomMargin=1.8 * cm,
        title="SCCSIMS Security Report",
        author="SCCSIMS",
    )
    page_w = A4[0] - doc.leftMargin - doc.rightMargin
    elems  = []

    # ─── FETCH DATA ────────────────────────────────────────────────────────────
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
        rogue_devices_live = list(rogue_cache)
        arp_results        = list(network_cache["arp"])

    arp_ips     = set(d["ip"] for d in arp_results)
    trusted_macs= set(normalize_mac(r[1]) for r in trusted_rows)
    trusted_ips = set(r[0] for r in trusted_rows)

    # ── Determine device statuses ──────────────────────────────────────────────
    current_time = datetime.now()
    devices_enriched = []
    for row in db_devices:
        hostname, ip, mac, os_, cpu, ram, loc, last_seen = row
        mac_norm = normalize_mac(mac)
        try:
            ls_time = datetime.strptime(str(last_seen), "%Y-%m-%d %H:%M:%S")
        except:
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
        })

    # ── Combine with ARP-only devices (not yet in DB) ─────────────────────────
    db_ips = set(d["ip"] for d in devices_enriched)
    for arp in arp_results:
        if arp["ip"] not in db_ips:
            mac_norm = normalize_mac(arp.get("mac", "unknown"))
            devices_enriched.append({
                "hostname": "—",
                "ip":       arp["ip"],
                "mac":      mac_norm,
                "os":       "—",
                "cpu":      0.0,
                "ram":      0.0,
                "location": "--",
                "last_seen":"—",
                "status":   "—",
                "trusted":  mac_norm in trusted_macs,
            })

    online_count  = sum(1 for d in devices_enriched if d["status"] == "ONLINE")
    offline_count = sum(1 for d in devices_enriched if d["status"] == "OFFLINE")
    total_count   = len(devices_enriched)
    rogue_count   = len(set(r["ip"] for r in rogue_devices_live))
    trusted_count = len(trusted_rows)

    # Unauthorized: in ARP / DB but MAC not trusted
    unauthorized_devices = [d for d in devices_enriched if not d["trusted"]]

    health     = calculate_system_health(total_count, rogue_count)
    health_cfg = HEALTH_CONFIG.get(health, HEALTH_CONFIG["UNKNOWN"])

    # ── GENERATE GRAPHS ────────────────────────────────────────────────────────
    cpu_path, rogue_path, pie_path, combined_path = generate_graphs(
        online_count=online_count,
        offline_count=offline_count,
        rogue_count=rogue_count,
        trusted_count=trusted_count,
    )

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  PAGE 1 — COVER / HEADER                                            ║
    # ╚══════════════════════════════════════════════════════════════════════╝

    # Logo + title block (sits inside the blue stripe painted by _on_first_page)
    try:
        logo_path = "static/logo.png"
        if os.path.exists(logo_path):
            logo_tbl = Table(
                [[Image(logo_path, width=70, height=35),
                  Paragraph("SCCSIMS Security Report", st["report_title"]),
                  ""]],
                colWidths=[80, page_w - 160, 80],
            )
            logo_tbl.setStyle(TableStyle([
                ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN",       (0, 0), (0, 0),   "LEFT"),
                ("ALIGN",       (1, 0), (1, 0),   "CENTER"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING",  (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING",(0,0), (-1, -1), 0),
            ]))
            elems.append(logo_tbl)
        else:
            elems.append(Paragraph("SCCSIMS Security Report", st["report_title"]))
    except Exception:
        elems.append(Paragraph("SCCSIMS Security Report", st["report_title"]))

    now_str = datetime.now().strftime("%A, %d %B %Y  •  %H:%M:%S")
    elems.append(Paragraph(f"Generated: {now_str}  |  Operator: {session.get('user','admin')}",
                            st["report_subtitle"]))
    elems.append(Spacer(1, 22))

    # ── SYSTEM HEALTH BANNER ───────────────────────────────────────────────────
    health_pill = ParagraphStyle(
        "HealthPill", parent=st["health_text"],
        textColor=health_cfg["color"],
        backColor=health_cfg["bg"],
        borderRadius=6, borderPad=8,
    )
    health_para = Paragraph(
        f"{health_cfg['icon']}  System Health: {health}",
        health_pill
    )
    health_tbl = Table([[health_para]], colWidths=[page_w])
    health_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), health_cfg["bg"]),
        ("LINEABOVE",     (0, 0), (-1, -1), 2, health_cfg["color"]),
        ("LINEBELOW",     (0, 0), (-1, -1), 2, health_cfg["color"]),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))
    elems.append(health_tbl)
    elems.append(Spacer(1, 16))

    # ── KPI STAT CARDS ─────────────────────────────────────────────────────────
    kpi_items = [
        ("Total Devices",  str(total_count),   RPT_ACCENT_BLUE,  RPT_LIGHT_BLUE),
        ("Online",         str(online_count),  RPT_GREEN,        RPT_LIGHT_GREEN),
        ("Offline",        str(offline_count), RPT_RED,          RPT_LIGHT_RED),
        ("Trusted",        str(trusted_count), HexColor("#006064"), HexColor("#e0f7fa")),
        ("Unauthorized",   str(len(unauthorized_devices)), RPT_ORANGE, RPT_LIGHT_ORANGE),
        ("Rogue Events",   str(rogue_count),   RPT_RED,          HexColor("#fce4ec")),
    ]

    kpi_cells = []
    for label, value, txt_color, bg_color in kpi_items:
        val_style = ParagraphStyle("KV", parent=st["kpi_value"], textColor=txt_color)
        cell = Table(
            [[Paragraph(value, val_style)],
             [Paragraph(label, st["kpi_label"])]],
            colWidths=[(page_w - 50) / 6]
        )
        cell.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), bg_color),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("LINEBELOW",     (0, 0), (-1, -1), 3, txt_color),
        ]))
        kpi_cells.append(cell)

    kpi_row = Table([kpi_cells], colWidths=[(page_w) / 6] * 6)
    kpi_row.setStyle(TableStyle([
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
    ]))
    elems.append(kpi_row)
    elems.append(Spacer(1, 20))

    # ── EXECUTIVE SUMMARY TABLE ────────────────────────────────────────────────
    elems.append(_section_divider("Executive Summary", st))
    elems.append(Spacer(1, 6))

    summary_data = [
        ["Metric", "Value", "Notes"],
        ["Total Devices Detected", str(total_count),
         "All devices observed via ARP & DB"],
        ["Online Devices", str(online_count),
         "Seen in current or recent ARP scan"],
        ["Offline Devices", str(offline_count),
         "Not found in ARP; last-seen timeout exceeded"],
        ["Trusted Devices", str(trusted_count),
         "Manually approved in the system"],
        ["Unauthorized Devices", str(len(unauthorized_devices)),
         "MAC not present in trusted list"],
        ["Active Rogue Events", str(rogue_count),
         "Detected during current scan cycle"],
        ["Total Attack Records", str(len(attacks)),
         "Cumulative history (last 20 shown)"],
        ["System Health Status", health,
         f"Based on rogue-to-total ratio ({rogue_count}/{total_count if total_count else 1})"],
    ]

    summary_tbl = Table(summary_data, colWidths=[page_w * 0.38, page_w * 0.18, page_w * 0.44])
    ts = _header_table_style()
    ts.add("ALIGN", (1, 1), (1, -1), "CENTER")
    ts.add("ALIGN", (2, 1), (2, -1), "LEFT")
    ts.add("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold")
    summary_tbl.setStyle(ts)
    elems.append(summary_tbl)

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  PAGE 2 — ALL DEVICES TABLE (online + offline, with status)         ║
    # ╚══════════════════════════════════════════════════════════════════════╝
    elems.append(PageBreak())
    elems.append(_section_divider(f"All Devices  ({total_count} total)", st))
    elems.append(Spacer(1, 6))
    elems.append(Paragraph(
        "Devices discovered via ARP scan and agent reports.  "
        "<b>Green = ONLINE</b> | <b>Red = OFFLINE</b>.",
        st["note"]
    ))
    elems.append(Spacer(1, 6))

    dev_header = ["#", "Hostname", "IP Address", "MAC Address",
                  "OS", "CPU%", "RAM%", "Location", "Last Seen", "Status"]
    dev_col_w  = [
        page_w * 0.035, page_w * 0.10, page_w * 0.09, page_w * 0.12,
        page_w * 0.09,  page_w * 0.055,page_w * 0.055,page_w * 0.085,
        page_w * 0.14,  page_w * 0.13,
    ]
    dev_data = [dev_header]
    for idx, d in enumerate(devices_enriched, 1):
        ls_display = d["last_seen"]
        try:
            ls_display = fmt_timestamp(d["last_seen"])
        except:
            pass
        dev_data.append([
            str(idx),
            d["hostname"],
            d["ip"],
            d["mac"],
            d["os"],
            f"{d['cpu']:.1f}",
            f"{d['ram']:.1f}",
            d["location"],
            ls_display,
            _status_pill(d["status"], st),
        ])

    dev_tbl = Table(dev_data, colWidths=dev_col_w, repeatRows=1)
    dev_ts  = _header_table_style()
    # colour offline rows
    for i, d in enumerate(devices_enriched, 1):
        if d["status"] == "OFFLINE":
            dev_ts.add("BACKGROUND", (0, i), (-2, i), HexColor("#fff8f8"))
        else:
            dev_ts.add("BACKGROUND", (0, i), (-2, i), RPT_WHITE)
    dev_tbl.setStyle(dev_ts)
    elems.append(dev_tbl)

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  PAGE 3 — TRUSTED DEVICES                                           ║
    # ╚══════════════════════════════════════════════════════════════════════╝
    elems.append(PageBreak())
    elems.append(_section_divider(f"Trusted Devices  ({trusted_count})", st))
    elems.append(Spacer(1, 6))

    if trusted_rows:
        tr_header = ["#", "IP Address", "MAC Address", "Device Name", "Location"]
        tr_col_w  = [
            page_w * 0.05, page_w * 0.22,
            page_w * 0.26, page_w * 0.25, page_w * 0.22,
        ]
        tr_data = [tr_header]
        for idx, r in enumerate(trusted_rows, 1):
            tr_data.append([str(idx), r[0] or "—", r[1] or "—",
                            r[2] or "Approved Device", r[3] or "—"])
        tr_tbl = Table(tr_data, colWidths=tr_col_w, repeatRows=1)
        tr_tbl.setStyle(_header_table_style(HexColor("#006064")))
        elems.append(tr_tbl)
    else:
        elems.append(Paragraph("No trusted devices registered.", st["note"]))

    elems.append(Spacer(1, 18))

    # ── UNAUTHORIZED DEVICES ───────────────────────────────────────────────────
    elems.append(_section_divider(
        f"Unauthorized Devices  ({len(unauthorized_devices)})", st))
    elems.append(Spacer(1, 6))

    if unauthorized_devices:
        ua_header = ["#", "Hostname", "IP Address", "MAC Address",
                     "OS", "Location", "Status"]
        ua_col_w  = [
            page_w * 0.04, page_w * 0.14, page_w * 0.14,
            page_w * 0.20, page_w * 0.13, page_w * 0.18, page_w * 0.17,
        ]
        ua_data = [ua_header]
        for idx, d in enumerate(unauthorized_devices, 1):
            ua_data.append([
                str(idx),
                d["hostname"], d["ip"], d["mac"],
                d["os"], d["location"],
                _status_pill(d["status"], st),
            ])
        ua_tbl = Table(ua_data, colWidths=ua_col_w, repeatRows=1)
        ua_ts  = _header_table_style(HexColor("#bf360c"))
        # tint every row in light orange
        for i in range(1, len(ua_data)):
            ua_ts.add("BACKGROUND", (0, i), (-2, i),
                      RPT_LIGHT_ORANGE if i % 2 == 1 else RPT_WHITE)
        ua_tbl.setStyle(ua_ts)
        elems.append(ua_tbl)
    else:
        elems.append(Paragraph(
            "No unauthorized devices detected — all observed MACs are trusted.",
            st["note"]))

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  PAGE 4 — ATTACK / ROGUE HISTORY                                    ║
    # ╚══════════════════════════════════════════════════════════════════════╝
    elems.append(PageBreak())
    elems.append(_section_divider(f"Attack & Rogue Event History  (last {len(attacks)})", st))
    elems.append(Spacer(1, 6))

    if attacks:
        atk_header = ["#", "IP Address", "MAC Address", "Attack Type",
                      "First Seen", "Last Seen"]
        atk_col_w  = [
            page_w * 0.04, page_w * 0.14, page_w * 0.18,
            page_w * 0.28, page_w * 0.18, page_w * 0.18,
        ]
        atk_data = [atk_header]
        for idx, a in enumerate(attacks, 1):
            atk_data.append([
                str(idx),
                a[0] or "—",
                a[1] or "—",
                a[2] or "—",
                fmt_timestamp(a[3]) if a[3] else "—",
                fmt_timestamp(a[4]) if a[4] else "—",
            ])
        atk_tbl = Table(atk_data, colWidths=atk_col_w, repeatRows=1)
        atk_ts  = _header_table_style(RPT_DARK_BLUE)
        # highlight spoofing / high-risk rows
        for i, a in enumerate(attacks, 1):
            atype = str(a[2] or "").lower()
            if "spoofing" in atype or "duplicate" in atype:
                atk_ts.add("BACKGROUND", (0, i), (-1, i), HexColor("#ffebee"))
                atk_ts.add("TEXTCOLOR",  (3, i), (3, i),  RPT_RED)
                atk_ts.add("FONTNAME",   (3, i), (3, i),  "Helvetica-Bold")
        atk_tbl.setStyle(atk_ts)
        elems.append(atk_tbl)
    else:
        elems.append(Paragraph("No attack records found in the database.", st["note"]))

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  PAGE 5 — ANALYTICS & GRAPHS                                        ║
    # ╚══════════════════════════════════════════════════════════════════════╝
    elems.append(PageBreak())
    elems.append(_section_divider("Network Analytics & Trend Graphs", st))
    elems.append(Spacer(1, 8))

    def _graph_block(img_path, caption_text, width=page_w, height=3 * inch):
        items = []
        if img_path and os.path.exists(img_path):
            # Bordered image frame
            img_tbl = Table(
                [[Image(img_path, width=width - 16, height=height)]],
                colWidths=[width]
            )
            img_tbl.setStyle(TableStyle([
                ("BOX",           (0, 0), (-1, -1), 0.8, HexColor("#c5cae9")),
                ("BACKGROUND",    (0, 0), (-1, -1), RPT_PALE_BLUE),
                ("TOPPADDING",    (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ]))
            items.append(img_tbl)
        else:
            items.append(Paragraph("Graph not available.", st["note"]))

        cap_style = ParagraphStyle(
            "GraphCaption", parent=st["note"],
            alignment=TA_CENTER, fontSize=7.5,
            textColor=RPT_GREY, spaceBefore=3
        )
        items.append(Paragraph(caption_text, cap_style))
        items.append(Spacer(1, 12))
        return items

    # CPU graph
    elems.extend(_graph_block(
        cpu_path,
        "Figure 1 — Average CPU usage across all monitored agents over the last 20 scan cycles.",
        height=2.5 * inch
    ))

    # Rogue graph
    elems.extend(_graph_block(
        rogue_path,
        "Figure 2 — Rogue device count detected per scan cycle. "
        "Spikes indicate new unauthorized MAC addresses appearing on the network.",
        height=2.5 * inch
    ))

    # Pie charts (side-by-side)
    elems.extend(_graph_block(
        pie_path,
        "Figure 3 — Left: Device status distribution (Online / Offline / Rogue).  "
        "Right: Trust distribution (Trusted vs Unauthorized).",
        height=3.0 * inch
    ))

    # Combined bar chart
    elems.extend(_graph_block(
        combined_path,
        "Figure 4 — Network activity bar chart comparing total devices vs rogue count "
        "across the last 20 scan cycles.",
        height=2.5 * inch
    ))

    # ── BUILD PDF ──────────────────────────────────────────────────────────────
    doc.build(
        elems,
        onFirstPage=_on_first_page,
        onLaterPages=_on_later_pages,
    )

    buffer.seek(0)
    ts_str   = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"SCCSIMS_Report_{ts_str}.pdf"
    return Response(
        buffer,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ═══════════════════════════════════════════════════════════════════════════════
# END REPORT SECTION
# ═══════════════════════════════════════════════════════════════════════════════


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