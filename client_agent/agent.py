import requests
import socket
import psutil
import platform
import time

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
API_KEY  = "secret123"
SERVER   = "http://[SERVER_IP]:5000/api/device"
LOCATION = "Lab"   # change per deployment: Lab / Library / Hostel / Admin Office

FAIL_COUNT = 0
MAX_FAIL   = 5
INTERVAL   = 2   # seconds between sends


def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "0.0.0.0"


def get_mac():
    try:
        nics = psutil.net_if_addrs()
        for name, addrs in nics.items():
            # skip loopback
            if name.lower() in ("lo", "loopback"):
                continue
            if name.lower().startswith("loopback"):
                continue
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    mac = addr.address
                    if mac and mac != "00:00:00:00:00:00":
                        return mac.lower()
    except:
        pass
    return "00:00:00:00:00:00"


# ─────────────────────────────────────────────
# Data Collection
# ─────────────────────────────────────────────
def collect_data():
    return {
        "hostname":    socket.gethostname() or "Unknown",
        "ip_address":  get_ip(),
        "mac_address": get_mac(),
        "os":          platform.system(),
        "cpu_usage":   psutil.cpu_percent(interval=None),
        "ram_usage":   psutil.virtual_memory().percent,
        "location":    LOCATION
    }


def is_server_alive():
    try:
        res = requests.get(
            SERVER.replace("/api/device", "/"),
            timeout=2
        )
        return res.status_code < 500
    except:
        return False

psutil.cpu_percent(interval=1)

print(f"🚀 Agent started → {SERVER}")
print(f"📍 Location: {LOCATION}")

# ─────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────
while True:
    try:
        if FAIL_COUNT >= MAX_FAIL:
            print(f"🔄 {FAIL_COUNT} failures — checking server...")
            if not is_server_alive():
                print("❌ Server still down, waiting 5s...")
                time.sleep(5)
                continue
            FAIL_COUNT = 0
            print("✅ Server back online, resuming...")

        data = collect_data()

        if data["ip_address"] == "0.0.0.0":
            print("⚠️  No network interface found, skipping...")
            time.sleep(INTERVAL)
            continue

        if data["mac_address"] == "00:00:00:00:00:00":
            print("⚠️  Could not read MAC address, skipping...")
            time.sleep(INTERVAL)
            continue

        res = requests.post(
            SERVER,
            json=data,
            headers={"API-KEY": API_KEY},
            timeout=2
        )

        print(f"📡 [{data['ip_address']}] CPU:{data['cpu_usage']}% RAM:{data['ram_usage']}% → {res.status_code}")
        FAIL_COUNT = 0

    except requests.exceptions.ConnectionError:
        print(f"⚠️  Connection refused ({FAIL_COUNT+1}/{MAX_FAIL})")
        FAIL_COUNT += 1

    except requests.exceptions.Timeout:
        print(f"⚠️  Request timed out ({FAIL_COUNT+1}/{MAX_FAIL})")
        FAIL_COUNT += 1

    except Exception as e:
        print(f"⚠️  Error ({FAIL_COUNT+1}/{MAX_FAIL}): {e}")
        FAIL_COUNT += 1

    time.sleep(INTERVAL)


# ─────────────────────────────────────────────
# DEPLOYMENT NOTES:
#
# 1. Build exe:
#    pip install pyinstaller
#    pyinstaller --onefile --noconsole agent.py
#
# 2. Change LOCATION and SERVER IP before building
#    each deployment copy.
#
# 3. Auto-start on Windows:
#    Place .exe in: shell:startup
#    (Win+R → shell:startup → paste shortcut)
#
# 4. SERVER IP must be static on the LAN.
#    Set static IP on server machine via router DHCP reservation.
# ─────────────────────────────────────────────