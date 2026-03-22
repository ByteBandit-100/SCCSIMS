import subprocess, socket, platform
from concurrent.futures import ThreadPoolExecutor

def get_network_prefix():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()

    return ".".join(ip.split(".")[:3]) + "."

network_prefix = get_network_prefix()

def ping(ip):
    for _ in range(2):
        if platform.system().lower() == "windows":
            command = f"ping -n 1 -w 500 {ip}"
        else:
            command = f"ping -c 1 -W 1 {ip}"

        result = subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if result == 0:
            return ip

    return None

def scan_network():
    ips = [network_prefix + str(i) for i in range(1,255)]
    active_devices = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        results = executor.map(ping, ips)

    for r in results:
        if r:
            active_devices.append(r)

    return active_devices

