import sqlite3

def get_user(uid):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return cursor.fetchall()

uid = input("uid: ")
print(get_user(uid))
