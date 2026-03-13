import requests
import socket
import platform
import psutil
import time

# 🔴 CHANGE THIS to your host machine IP
SERVER_URL = "http://192.168.1.33:5000/api/device"  #here the ip 192.168.1.33 is fixed ip by router for testing it is server ip where app.py executes

LOCATION = "Library"  #location must be lab,library,hostel or admin staff client sections

def get_system_data():
    hostname = socket.gethostname()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    s.close()

    os_name = platform.system() + " " + platform.release()
    cpu_usage = psutil.cpu_percent(interval=1)
    ram_usage = psutil.virtual_memory().percent

    return{
        "hostname": hostname,
        "ip_address": ip_address,
        "os": os_name,
        "cpu_usage": cpu_usage,
        "ram_usage": ram_usage,
        "location": LOCATION
    }

while True:
    try:
        data = get_system_data()
        response = requests.post(SERVER_URL, json=data)
        print("Data sent:", response.json())

    except Exception as e:
        print("Error:", e)

    time.sleep(10)  # send every 10 seconds
