import sqlite3

def get_user(uid):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    params = {"query": "SELECT * FROM users WHERE id = ?", "args": (int(uid),)}
    cursor.execute(params["query"], params["args"])
    return cursor.fetchall()

uid = input("uid: ")
print(get_user(uid))
