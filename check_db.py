import sqlite3

conn = sqlite3.connect("rtasa.db")
cursor = conn.cursor()

share_id = "04d162ab-4bd2-4f4d-829c-6355e7536d0c"

print("Checking shares table:")
cursor.execute(
    "SELECT * FROM shares WHERE id=?",
    (share_id,)
)
print(cursor.fetchall())


print("Checking share_records table:")
cursor.execute(
    "SELECT * FROM share_records WHERE id=?",
    (share_id,)
)
print(cursor.fetchall())

conn.close()