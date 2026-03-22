import requests
import socket
import psutil
import platform
import time
import uuid

# -----------------------------
# CONFIG (STATIC SERVER)
# -----------------------------
API_KEY = "secret123"
SERVER = "http://192.168.1.33:5000/api/device"

FAIL_COUNT = 0
MAX_FAIL = 5   # after 5 fails → wait & retry


# -----------------------------
# Get IP
# -----------------------------
def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "0.0.0.0"


# -----------------------------
# Get MAC
# -----------------------------
def get_mac():
    return ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff)
                    for i in range(0, 8*6, 8)][::-1])


# -----------------------------
# Collect System Data (FAST)
# -----------------------------
def collect_data():
    return {
        "hostname": socket.gethostname() or "Unknown",
        "ip_address": get_ip(),
        "mac_address": get_mac(),
        "os": platform.system(),
        "cpu_usage": psutil.cpu_percent(interval=None),  # ⚡ non-blocking
        "ram_usage": psutil.virtual_memory().percent,
        "location": "Lab"  #location must be library, lab, hostel, admin office etc change manually
    }


# -----------------------------
# Check server alive
# -----------------------------
def is_server_alive():
    try:
        res = requests.post(
            SERVER,
            json={"ping": "test"},
            headers={"API-KEY": API_KEY},
            timeout=2
        )
        return res.status_code in [200, 400]
    except:
        return False


# -----------------------------
# MAIN LOOP (STATIC + RESILIENT)
# -----------------------------
print(f"🚀 Agent started → Server: {SERVER}")

while True:
    try:
        # Optional: quick health check if many failures
        if FAIL_COUNT >= MAX_FAIL:
            print("🔄 Server unreachable, retrying connection...")
            if not is_server_alive():
                time.sleep(3)
                continue
            FAIL_COUNT = 0  # reset if server is back

        data = collect_data()

        res = requests.post(
            SERVER,
            json=data,
            headers={"API-KEY": API_KEY},
            timeout=2
        )

        print(f"📡 Sent: {res.status_code}")

        # ✅ Reset fail count on success
        FAIL_COUNT = 0

    except Exception as e:
        print("⚠️ Error:", e)

        FAIL_COUNT += 1

        # Small delay to avoid hammering
        time.sleep(1)
        continue

    # 🚀 SEND EVERY 2 SECOND (REAL-TIME)
    time.sleep(2)


# To run this file automatically on the clients:
# make it .exe using pyinstaller and remember for different location change the location and server ip manyally
# the place .exe file on shell:startup programs in windows  it runs automatically in background
# when it connects to network it sends data to the manually changed server (server ip must be static)

