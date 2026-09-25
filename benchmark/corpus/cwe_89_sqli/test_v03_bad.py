import sqlite3

def get_user(uid):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    params = {"query": f"SELECT * FROM users WHERE id = {uid}"}
    cursor.execute(params["query"])
    return cursor.fetchall()

uid = input("uid: ")
print(get_user(uid))
