import sqlite3


def sink(statement):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    return cursor.execute("SELECT * FROM t WHERE id = " + statement)
