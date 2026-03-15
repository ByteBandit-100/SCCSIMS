import sqlite3

conn = sqlite3.connect("./sccsims.db")
cursor = conn.cursor()


# ensure table exists
cursor.execute("""
CREATE TABLE IF NOT EXISTS trusted_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT,
    mac_address TEXT,
    device_name TEXT,
    location TEXT
)
""")

# # Adding Trusted devices
# cursor.execute("""
# INSERT INTO trusted_devices
# (ip_address, mac_address, device_name, location)
# VALUES
# ('IP','MAC','DEVICE_NAME','LOCATION')
# """) # EXAMPLE VALUES('192.168.1.33','14:ac:60:48:34:4G','Hp','Pc-Server')
#
# print("Trusted device inserted successfully")

#TO LIST TRUSTED DEVICE TABLE :
cursor.execute("SELECT * FROM trusted_devices")

for row in cursor.fetchall():
    print(row)

conn.commit()
conn.close()