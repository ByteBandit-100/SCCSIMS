import sqlite3

conn = sqlite3.connect("sccsims.db")
cursor = conn.cursor()

cursor.execute("DELETE FROM scan_history WHERE ports IS NULL OR ports=''")

conn.commit()
conn.close()