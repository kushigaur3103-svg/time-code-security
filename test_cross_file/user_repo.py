import sqlite3

def find_user_by_name(raw_name):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Direct SQL Injection sink
    cursor.execute("SELECT * FROM users WHERE username = '" + raw_name + "'")
    return cursor.fetchall()