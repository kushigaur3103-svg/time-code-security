import sqlite3

class UserRepo:
    def __init__(self, uid):
        self.uid = int(uid)

    def fetch(self):
        conn = sqlite3.connect("app.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (self.uid,))
        return cursor.fetchall()

uid = input("uid: ")
repo = UserRepo(uid)
print(repo.fetch())
