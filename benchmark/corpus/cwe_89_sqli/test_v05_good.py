import sqlite3

def get_entity(uid, is_admin):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    table = "admins" if is_admin else "users"
    cursor.execute(f"SELECT * FROM {table} WHERE id = ?", (int(uid),))
    return cursor.fetchall()

uid = input("uid: ")
print(get_entity(uid, False))
