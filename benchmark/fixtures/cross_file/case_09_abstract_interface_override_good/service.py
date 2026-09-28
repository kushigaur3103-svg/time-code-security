import sqlite3

from base import BaseHandler


class SafeHandler(BaseHandler):
    def fetch_rows(self, user_id):
        connection = sqlite3.connect("registry.db")
        cursor = connection.cursor()
        return cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
