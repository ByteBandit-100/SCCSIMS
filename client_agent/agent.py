import requests
import socket
import platform
import psutil
import time

# 🔴 CHANGE THIS to your host machine IP
SERVER_URL = "http://192.168.1.34:5000/api/device"

def get_system_data():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    os_name = platform.system() + " " + platform.release()
    cpu_usage = psutil.cpu_percent(interval=1)
    ram_usage = psutil.virtual_memory().percent

    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "os": os_name,
        "cpu_usage": cpu_usage,
        "ram_usage": ram_usage
    }

while True:
    try:
        data = get_system_data()
        response = requests.post(SERVER_URL, json=data)
        print("Data sent:", response.json())

    except Exception as e:
        print("Error:", e)

    time.sleep(10)  # send every 10 seconds
