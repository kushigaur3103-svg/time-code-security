import sqlite3

def get_entity(uid, is_admin):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    if is_admin:
        q = f"SELECT * FROM admins WHERE id = {uid}"
    else:
        q = f"SELECT * FROM users WHERE id = {uid}"
    cursor.execute(q)
    return cursor.fetchall()

uid = input("uid: ")
print(get_entity(uid, False))
