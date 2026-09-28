import sqlite3


class BaseHandler:
    def fetch_rows(self, user_id):
        connection = sqlite3.connect("registry.db")
        cursor = connection.cursor()
        return cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
