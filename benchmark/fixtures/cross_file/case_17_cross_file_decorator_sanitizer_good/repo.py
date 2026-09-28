import sqlite3


def query_db(val):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    return cursor.execute("SELECT * FROM t WHERE id = " + val)
