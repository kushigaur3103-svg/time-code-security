import sqlite3

class UserRepo:
    def __init__(self, uid):
        self.query = f"SELECT * FROM users WHERE id = {uid}"

    def fetch(self):
        conn = sqlite3.connect("app.db")
        cursor = conn.cursor()
        cursor.execute(self.query)
        return cursor.fetchall()

uid = input("uid: ")
repo = UserRepo(uid)
print(repo.fetch())
