import sqlite3

def build_query(uid):
    return f"SELECT * FROM users WHERE id = {uid}"

def get_user(uid):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = build_query(uid)
    cursor.execute(query)
    return cursor.fetchall()

uid = input("uid: ")
print(get_user(uid))
