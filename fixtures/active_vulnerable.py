from flask import request
import sqlite3

def test():
    user_id = request.args.get("user")
    db = sqlite3.connect("app.db")
    db.execute(f"SELECT * FROM users WHERE id = {user_id}")
