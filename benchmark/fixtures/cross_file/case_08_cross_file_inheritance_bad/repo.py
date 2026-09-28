import sqlite3


class BaseRepo:
    def fetch_rows(self, statement):
        connection = sqlite3.connect("catalog.db")
        cursor = connection.cursor()
        return cursor.execute("SELECT * FROM records WHERE id = '" + statement + "'")
