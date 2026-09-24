from flask import request
import sqlite3

def handle_user_lookup():
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = ?"
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(query, (user_id,))
    return cursor.fetchall()
