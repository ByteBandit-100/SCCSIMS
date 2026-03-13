from flask import Flask, request, jsonify
import sqlite3
from flask import render_template
from network_scanner import scan_network
from datetime import datetime

app = Flask(__name__)
DATABASE = "sccsims.db"

@app.route("/")
def dashboard():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM devices")
    rows = cursor.fetchall()
    conn.close()

    devices = []
    current_time = datetime.now()

    for row in rows:
        try:
            last_seen_time = datetime.strptime(row[7], "%Y-%m-%d %H:%M:%S")
        except:
            last_seen_time = current_time

        time_diff = (current_time - last_seen_time).total_seconds()

        status = "ONLINE" if time_diff <= 60 else "OFFLINE"

        devices.append({
            "id": row[0],
            "hostname": row[1],
            "ip_address": row[2],
            "os": row[3],
            "cpu_usage": row[4],
            "ram_usage": row[5],
            "location": row[6],
            "last_seen": row[7],
            "status": status
        })

    return render_template("dashboard.html", devices=devices)
# ---------------------------
# Database Initialization
# ---------------------------
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS devices
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       hostname
                       TEXT,
                       ip_address
                       TEXT,
                       os
                       TEXT,
                       cpu_usage
                       REAL,
                       ram_usage
                       REAL,
                       location
                       TEXT,
                       last_seen
                       TEXT
                   )
                   """)
    conn.commit()
    conn.close()
# ---------------------------
# Receive Data from Clients
# ---------------------------
@app.route("/api/device", methods=["POST"])
def receive_device_data():
    data = request.json

    hostname = data.get("hostname")
    ip_address = data.get("ip_address")
    os_name = data.get("os")
    cpu_usage = data.get("cpu_usage")
    ram_usage = data.get("ram_usage")
    location = data.get("location", "Unknown")

    last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM devices WHERE ip_address = ?", (ip_address,))
    device = cursor.fetchone()

    if device:
        cursor.execute("""
                       UPDATE devices
                       SET hostname=?,
                           os=?,
                           cpu_usage=?,
                           ram_usage=?,
                           location=?,
                           last_seen=?
                       WHERE ip_address = ?
                       """, (hostname, os_name, cpu_usage, ram_usage, location, last_seen, ip_address))
    else:
        cursor.execute("""
                       INSERT INTO devices
                           (hostname, ip_address, os, cpu_usage, ram_usage, location, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       """, (hostname, ip_address, os_name, cpu_usage, ram_usage, location, last_seen))

    conn.commit()
    conn.close()

    return jsonify({"status": "Device data stored successfully"}), 200# ---------------------------
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
            "os": row[3],
            "cpu_usage": row[4],
            "ram_usage": row[5],
            "location" : row[6],
            "last_seen": row[7]
        })

    return jsonify(devices)


@app.route("/scan-network")
def scan_network_route():
    devices = scan_network()
    return jsonify(devices)

# ---------------------------
# Run Server
# ---------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)

